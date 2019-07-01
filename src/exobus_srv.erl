%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2017, Tony Rogvall
%%% @doc
%%%    exo_socket server for xbus
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
	  client_chal,     %% challenge recived by client
	  server_chal,     %% challenge sent to client
	  socket,
	  clients,
	  ping_request = false :: boolean(),  %% seen ping request
	  ping_count,      %% client_count at time for ping monitor
	  args,
	  sublist = [],
	  timediff = 0     %% timestamp diff between client and server
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
    Send_t = proplists:get_value(send_timeout, Args, ?SEND_TIMEOUT),
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
	Mesg={auth_req,#{id:=ClientID,chal:=Chal,timestamp:=ClientTs}}
	  when State#state.state =:= auth0 ->
	    TimeStamp = xbus:timestamp(), %% as early as possible
	    case lists:keyfind(ClientID, 1, State#state.clients) of
		false ->
		    {stop, {unknow_client_id}, State};
		{_,CArgs} ->
		    Args  = CArgs ++ State#state.args,
		    SKey  = key(proplists:get_value(server_key, Args)),
		    CKey  = key(proplists:get_value(client_key, Args)),
		    Chal1 = crypto:strong_rand_bytes(16),
		    TimeDiff = TimeStamp - ClientTs,
		    State1 = State#state { client_id = ClientID,
					   client_count = Count,
					   state = auth1,
					   client_key = CKey,
					   server_key = SKey,
					   server_chal = Chal1,
					   client_chal = Chal,
					   timediff = TimeDiff },
		    case verify(State1,Hash,Count,Bin) of
			{ok,State2} ->
			    Cred  = crypto:hash(sha,[SKey,Chal]),
			    Res = {auth_res,#{id=>State2#state.server_id,
					      chal=>Chal1,
					      cred=>Cred,
					      timestamp=>xbus:timestamp()
					     }},
			    State3 = send(State2,Res),
			    {ok,State3};
			Error ->
			    lager:error("message error ~p mesg ~p",
					[Error,Mesg]),
			    {stop,Error,State}
		    end
	    end;

	Mesg={auth_ack,#{id:=ClientID,cred:=Cred}}
	  when State#state.state =:= auth1,
	       State#state.client_id =:= ClientID ->
	    case verify(State,Hash,Count,Bin) of
		{ok,State1} ->
		    case crypto:hash(sha,[State1#state.client_key,
					  State1#state.server_chal]) of
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

info(_Socket, Info={xbus,_TopicPattern,_Map}, State) 
  when State#state.state =:= open ->
    %% io:format("xbus message ~p\n", [Info]),
    State1 = send(State, Info),
    {ok,State1};
info(_Socket, Info={xbus_meta,_TopicPattern,_Map}, State) 
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
	    {Reply,SubList1} = do_subscribe(TopicList,SubList,false),
	    State1 = send(State, {reply,ID, Reply}),
	    %% must add it again, instead of reference count
	    {ok, State1#state { sublist = SubList1 }};

	{sub_meta,TopicList} when is_list(TopicList) ->
	    SubList = State#state.sublist,
	    {Reply,SubList1} = do_subscribe(TopicList,SubList,meta),
	    State1 = send(State, {reply,ID, Reply}),
	    %% must add it again, instead of reference count
	    {ok, State1#state { sublist = SubList1 }};

	{sub_ack,TopicList} when is_list(TopicList) ->
	    SubList = State#state.sublist,
	    {Reply,SubList1} = do_subscribe(TopicList,SubList,true),
	    State1 = send(State, {reply,ID, Reply}),
	    %% must add it again, instead of reference count
	    {ok, State1#state { sublist = SubList1 }};

	{ack,Topic} ->
	    Reply = xbus:ack(Topic),
	    State1 = send(State,{reply,ID,Reply}),
	    {ok,State1};

	{unsub,TopicList} when is_list(TopicList) ->
	    SubList = State#state.sublist,
	    {Reply,SubList1} = do_unsubscribe(TopicList,SubList,data),
	    State1 = send(State, {reply,ID, Reply}),
	    %% must add it again, instead of reference count
	    {ok, State1#state { sublist = SubList1 }};

	{unsub_meta,TopicList} when is_list(TopicList) ->
	    SubList = State#state.sublist,
	    {Reply,SubList1} = do_unsubscribe(TopicList,SubList,meta),
	    State1 = send(State, {reply,ID, Reply}),
	    %% must add it again, instead of reference count
	    {ok, State1#state { sublist = SubList1 }};

	{pub,Topic,Value} ->
	    Reply = xbus:pub(Topic,Value),
	    State1 = send(State,{reply,ID,Reply}),
	    {ok,State1};

	{pub,Topic,Value,TimeStamp} ->
	    TimeStamp1 = TimeStamp + State#state.timediff,
	    Reply = xbus:pub(Topic,Value,TimeStamp1),
	    State1 = send(State,{reply,ID,Reply}),
	    {ok,State1};

	{pub_meta,Topic,Value} ->
	    Reply = xbus:pub_meta(Topic,Value),
	    State1 = send(State,{reply,ID,Reply}),
	    {ok,State1};

	_ ->
	    lager:error("bad call received ~p", [Request]),
	    send(State,{reply,ID,{error,einval}}),
	    {stop,{error,einval},State}
    end.

do_subscribe(Topics, SubList, Variant0) ->
    {Variant,Ack} = case Variant0 of
			true  -> {data, true};
			false -> {data, false};
			meta  -> {meta, false}
		    end,
    do_subscribe_(Topics,SubList,Variant,Ack,true).

do_subscribe_([Topic|Ts],SubList,Variant,Ack,Reply) ->
    case lists:member({Topic,Variant},SubList) of
	true -> %% already in list, just add reference (fixme Ack?)
	    do_subscribe_(Ts,[{Topic,Variant}|SubList],Variant,Ack,Reply);
	false ->
	    R = case Variant of
		    data when Ack -> %% fixme: first subscribe dictates ack!
			xbus:sub_ack(Topic);
		    data ->
			xbus:sub(Topic);
		    meta ->
			xbus:sub_meta(Topic)
		end,
	    case R of
		true ->
		    do_subscribe_(Ts,[{Topic,Variant}|SubList],
				 Variant,Ack,Reply);
		Reply1 ->
		    do_subscribe_(Ts,[{Topic,Variant}|SubList],
				 Variant,Ack,Reply1)
	    end
    end;
do_subscribe_([],SubList,_Variant,_Ack,Reply) ->
    {Reply, SubList}.

do_unsubscribe(Topics, SubList, Variant) ->
    do_unsubscribe(Topics, SubList, Variant, true).

do_unsubscribe([Topic|Ts], SubList, Variant, Reply) ->
    SubList1 = lists:delete({Topic,Variant}, SubList),
    case lists:member({Topic,Variant}, SubList1) of %% the last instance?
	true ->
	    do_unsubscribe(Ts, SubList1, Variant, Reply);
	false -> %% yes do real unsub
	    R = case Variant of
		    data -> xbus:unsub(Topic);
		    meta -> xbus:unsub_meta(Topic)
		end,
	    case R of
		true ->
		    do_unsubscribe(Ts, SubList1, Variant, Reply);
		Reply1 ->
		    do_unsubscribe(Ts, SubList1, Variant, Reply1)
	    end
    end;
do_unsubscribe([], SubList, _Variant, Reply) ->
    {Reply, SubList}.


send(State, Message) ->
    Bin    = term_to_binary(Message),
    Count  = State#state.server_count,
    %% FIXME: include State#state.server_chal in Hash
    Hash   = crypto:hash(sha,[State#state.server_key,<<Count:64>>,Bin]),
    lager:debug("send: HASH skey=~p ~p ~p = ~p",
		[State#state.server_key,Count,Bin,Hash]),
    Packet = <<Hash:?HSIZE/binary,Count:?CSIZE,Bin/binary>>,
    ok = exo_socket:send(State#state.socket, Packet),
    State#state { server_count = Count + 1}.

verify(State,Hash,Count,Bin) ->
    if State#state.client_count =:= Count ->
	    %% FIXME: include State#state.client_chal in Hash
	    Hash1 = crypto:hash(sha,[State#state.client_key,<<Count:64>>,Bin]),
	    if Hash1 =:= Hash ->
		    {ok,State#state { client_count = next_count(Count) }};
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

next_count(Count) ->
    if Count >= 16#ffffffffffffffff -> 0; %% wrap
       true -> Count+1
    end.

irand64() ->
    <<R:64>> = crypto:strong_rand_bytes(8),
    R.

key(Key) when is_integer(Key) -> <<Key:64>>;
key(Key) when is_binary(Key) ->  Key;
key(Key) when is_list(Key) ->    iolist_to_binary(Key);
key(Key) when is_atom(Key) ->    atom_to_binary(Key,latin1).
