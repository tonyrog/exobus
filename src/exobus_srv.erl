%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2017, Tony Rogvall
%%% @doc
%%%    exo http server access to erlbus
%%% @end
%%% Created : 20 Apr 2017 by Tony Rogvall <tony@rogvall.se>

-module(exobus_srv).

-export([start/0]).
-export([start_link/1]).

-behaviour(exo_socket_server).
-export([init/2, data/3, close/2, error/3, control/4, info/3]).

-define(IDLE_TIMEOUT, (30*1000)).  %% 30 seconds
-define(SEND_TIMEOUT, (10*1000)).  %% 10 seconds

-record(state,
	{
	  server_id,
	  client_id,
	  state = closed :: closed | auth | open,
	  server_key,
	  client_key,
	  server_count = 0,
	  client_count = 0,
	  chal,
	  socket,
	  clients,
	  ping_request = false :: boolean(),  %% seen ping request
	  ping_count,      %% client_count at time for ping monitor
	  args,
	  sublist = []
	}).

-define(HSIZE, 20).  %% hash is sha 
-define(CSIZE, 64).  %% count is 64 bit


start() ->
    application:ensure_all_started(exobus).

start_link(Args0) ->
    Args = Args0 ++ application:get_all_env(exobus),
    Port = proplists:get_value(server_port, Args, 17831),
    IfAddr =  proplists:get_value(ifaddr, Args, {0,0,0,0}),
    Idle_t = proplists:get_value(idle_timeout, Args, ?IDLE_TIMEOUT),
    Send_t = proplists:get_value(send_timeout, Args, ?IDLE_TIMEOUT),
    %% interface address ssl options etc
    exo_socket_server:start_link(Port, [tcp], 
				 [{packet,4},{mode,binary},{active,once},
				  {reuseaddr,true},{nodelay,true},
				  {ifaddr,IfAddr},{send_timeout,Send_t}],
				 ?MODULE, [{idle_timeout,Idle_t}]).

init(Socket, Args0) ->
    Args = Args0 ++ application:get_all_env(exobus),
    Clients    = proplists:get_value(clients, Args),
    Args1      = proplists:delete(clients, Args),
    ServerID   = proplists:get_value(id, Args),
    {ok, #state { server_id = ServerID, 
		  sublist = [],
		  state = auth0,
		  socket = Socket,
		  server_count = irand64(),
		  clients = Clients, args = Args1 }}.

data(_Socket, <<Hash:?HSIZE/binary,Count:?CSIZE,Bin/binary>>, State) ->
    try binary_to_term(Bin) of
	Mesg={auth_req, [{id,ClientID},{chal,Chal}]}
	  when State#state.state =:= auth0 ->
	    case lists:keyfind(ClientID, 1, State#state.clients) of
		false ->
		    {stop, {unknow_client_id}, State};
		{_,CArgs} ->
		    Args  = CArgs ++ State#state.args,
		    SKey  = key(proplists:get_value(server_key, Args)),
		    CKey  = key(proplists:get_value(client_key, Args)),
		    Chal1 = crypto:strong_rand_bytes(16),
		    State1 = State#state { client_id = ClientID,
					   client_count = Count,
					   state = auth1,
					   client_key = CKey,
					   server_key = SKey,
					   chal = Chal1 },
		    case verify(State1,Hash,Count,Bin) of
			{ok,State2} ->
			    Cred  = crypto:hash(sha,[SKey,Chal]),
			    Res = {auth_res,[{id,State2#state.server_id},
					     {chal,Chal1},{cred,Cred}]},
			    State3 = send(State2,Res),
			    {ok,State3};
			Error ->
			    lager:error("message error ~p mesg ~p",
					[Error,Mesg]),
			    {stop,Error,State}
		    end
	    end;

	Mesg={auth_ack,[{id,ClientID},{cred,Cred}]}
	  when State#state.state =:= auth1,
	       State#state.client_id =:= ClientID ->
	    case verify(State,Hash,Count,Bin) of
		{ok,State1} ->
		    case crypto:hash(sha,[State1#state.client_key,
					  State1#state.chal]) of
			Cred ->
			    {ok, State1#state { state = open }};
			_ ->
			    {stop, {bad_credentials}, State}
		    end;
		Error ->
		    lager:error("message error ~p mesg ~p",
				[Error,Mesg]),
		    {stop,Error,State}
	    end;

	{call,ID,Request} when State#state.state =:= open ->
	    case verify(State,Hash,Count,Bin) of
		{ok,State1} ->
		    handle_call(ID, Request,State1);
		{error,Reason} = Error ->
		    lager:error("packet error ~p on request ~p",
				[Reason, Request]),
		    {stop,Error,State}
	    end;

	ping when State#state.state =:= open ->
	    case verify(State,Hash,Count,Bin) of
		{ok,State1} ->
		    State2 = send(State1, ping_res),
		    State3 = State2#state {
			       ping_request = true,
			       ping_count = State2#state.client_count},
		    {ok, State3};
		{error,Reason} = Error ->
		    lager:error("packet error ~p on ping request",
				[Reason]),
		    {stop,Error,State}
	    end;

	_Term ->
	    lager:error("unknown data received ~p", [_Term]),
	    {stop,{error,einval},State}
    catch
	error:Reason ->
	    lager:error("internal error ~p", [{error,Reason}]),
	    {stop,{error,Reason},State}
    end.

close(_Socket, State) ->
    lager:debug("exobus got close"),
    {ok, State}.

error(_Socket, Error, State) ->
    lager:error("exobus socket error ~p", [Error]),
    {stop, Error, State}.

control(_Socket, _Request, _From, State) ->
    lager:debug("exobus request ~p", [_Request]),
    {noreply, State}.

info(_Socket, Info={xbus,_TopicPattern,_Topic,_Value}, State) 
  when State#state.state =:= open ->
    State1 = send(State, Info),
    {ok,State1};
info(_Socket, Info, State) ->
    lager:debug("exobus info ~p", [Info]),
    {ok, State}.

handle_call(ID,Request,State) ->
    case Request of
	{sub,TopicList} when is_list(TopicList) ->
	    SubList = State#state.sublist,
	    {Reply,SubList1} = do_subscribe(TopicList,SubList),
	    State1 = send(State, {reply,ID, Reply}),
	    %% must add it again, instead of reference count
	    {ok, State1#state { sublist = SubList1 }};

	{unsub,TopicList} when is_list(TopicList) ->
	    SubList = State#state.sublist,
	    {Reply,SubList1} = do_unsubscribe(TopicList,SubList),
	    State1 = send(State, {reply,ID, Reply}),
	    %% must add it again, instead of reference count
	    {ok, State1#state { sublist = SubList1 }};

	{pub,Topic,Value} ->
	    Reply = xbus:pub(Topic,Value),
	    State1 = send(State,{reply,ID,Reply}),
	    {ok,State1};
	_ ->
	    lager:error("bad call received ~p", [Request]),
	    send(State,{reply,ID,{error,einval}}),
	    {stop,{error,einval},State}
    end.

do_subscribe(Topics, SubList) ->
    do_subscribe(Topics,SubList,ok).

do_subscribe([Topic|Ts],SubList,Reply) ->
    case lists:member(Topic,SubList) of
	true ->
	    do_subscribe(Ts,[Topic|SubList],Reply);
	false ->
	    case xbus:sub(Topic) of
		true ->
		    do_subscribe(Ts,[Topic|SubList],Reply);
		Reply1 ->
		    do_subscribe(Ts,[Topic|SubList],Reply1)
	    end
    end;
do_subscribe([],SubList,Reply) ->
    {Reply, SubList}.

do_unsubscribe(Topics, SubList) ->
    do_unsubscribe(Topics, SubList, ok).

do_unsubscribe([Topic|Ts], SubList, Reply) ->
    SubList1 = lists:delete(Topic, SubList),
    case lists:member(Topic, SubList1) of
	true ->
	    do_unsubscribe(Ts, SubList1, Reply);
	false ->
	    case xbus:unsub(Topic) of
		true ->
		    do_unsubscribe(Ts, SubList1, Reply);
		Reply1 ->
		    do_unsubscribe(Ts, SubList1, Reply1)
	    end
    end;
do_unsubscribe([], SubList, Reply) ->
    {Reply, SubList}.


send(State, Message) ->
    Bin    = term_to_binary(Message),
    Count  = State#state.server_count,
    Hash   = crypto:hash(sha,[State#state.server_key,<<Count:64>>,Bin]),
    lager:debug("send: HASH skey=~p ~p ~p = ~p",
		[State#state.server_key,Count,Bin,Hash]),
    Packet = <<Hash:?HSIZE/binary,Count:?CSIZE,Bin/binary>>,
    ok = exo_socket:send(State#state.socket, Packet),
    State#state { server_count = Count + 1}.

verify(State,Hash,Count,Bin) ->
    if State#state.client_count =:= Count ->
	    Hash1 = crypto:hash(sha,[State#state.client_key,<<Count:64>>,Bin]),
	    if Hash1 =:= Hash ->
		    {ok,State#state { client_count = Count+1 }};
		true ->
		    lager:error("verify: HASH ckey=~p ~p ~p = ~p (expect ~p)", 
				[State#state.client_key,Count,Bin,Hash1,Hash]),
		    {error,bad_signature}
	    end;
       true ->
	    lager:error("verify: Count=~w, expected=~w",
			[Count, State#state.client_count]),
	    {error, bad_count}
    end.

irand64() ->
    <<R:64>> = crypto:strong_rand_bytes(8),
    R.

key(Key) when is_integer(Key) -> <<Key:64>>;
key(Key) when is_binary(Key) ->  Key;
key(Key) when is_list(Key) ->    iolist_to_binary(Key);
key(Key) when is_atom(Key) ->    atom_to_binary(Key,latin1).
