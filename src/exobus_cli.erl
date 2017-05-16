%%%-------------------------------------------------------------------
%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2017, Tony Rogvall
%%% @doc
%%%    exobus TCP client
%%% @end
%%% Created : 21 Apr 2017 by Tony Rogvall <tony@rogvall.se>
%%%-------------------------------------------------------------------
-module(exobus_cli).

-behaviour(gen_server).

-include_lib("exo/src/exo_socket.hrl").

-type exo_socket() :: #exo_socket{}.

%% API
-export([start_link/1]).
-export([sub/2]).
-export([unsub/2]).
-export([pub/3]).
-export([pub/4]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(DEFAULT_CONNECT_TIMEOUT,    3000).
-define(DEFAULT_RECONNECT_INTERVAL, 4000).
-define(DEFAULT_AUTH_TIMEOUT,       3000).
-define(DEFAULT_PING_INTERVAL,      10000).

-define(HSIZE, 20).  %% hash is sha 
-define(CSIZE, 64).  %% count is 64 bit

-record(state,
	{
	  id,           %% id used by the server (used for authentication)
	  name,         %% server name in config
	  server_name,  %% name of server, as known by server
	  state = closed :: closed | auth | open,
	  server_ip,
	  server_port,
	  server_key,
	  client_key,
	  server_count,
	  client_count,
	  chal,           %% challenge sent to server
	  socket :: exo_socket(),
	  reconnect_interval,
	  reconnect_timer,
	  auth_timeout,
	  auth_timer,
	  ping_interval,  %% send keep alive ping 
	  ping_timer,
	  ping_count,
	  ping_response = false :: boolean(),
	  topic_list = [],
	  wait_send = [],
	  wait_recv = [],
	  timediff = 0     %% timestamp diff between client and server
	}).

%%%===================================================================
%%% API
%%%===================================================================

sub(Pid,TopicPattern) ->
    gen_server:call(Pid, {sub,TopicPattern}).

unsub(Pid,TopicPattern) ->
    gen_server:call(Pid, {unsub,TopicPattern}).

pub(Pid,Topic,Value) ->
    gen_server:call(Pid, {pub,Topic,Value}).

pub(Pid,Topic,Value,TimeStamp) ->
    gen_server:call(Pid, {pub,Topic,Value,TimeStamp}).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init(Opts) ->
    Name = proplists:get_value(name, Opts),
    Env = application:get_all_env(exobus),
    Servers = proplists:get_value(servers, Env),
    {_,Args0} = lists:keyfind(Name, 1, Servers),
    Args1 = proplists:delete(servers, Env),
    Args = Args0 ++ Args1,
    Port = proplists:get_value(server_port, Args, 17831),
    Host = proplists:get_value(server_ip, Args, "127.0.0.1"),
    SKey = key(proplists:get_value(server_key, Args)),
    CKey = key(proplists:get_value(client_key, Args)),
    ID   = proplists:get_value(id, Args),
    TopicList = proplists:get_value(subscribe, Args, []),
    Reconnect_i = proplists:get_value(reconnect_interval, Args,
				      ?DEFAULT_RECONNECT_INTERVAL),
    Ping_i = proplists:get_value(ping_interval, Args,
				 ?DEFAULT_PING_INTERVAL),
    Auth_t = proplists:get_value(auth_timeout, Args, ?DEFAULT_AUTH_TIMEOUT),
    connect(#state { id=ID,
		     name=Name,
		     server_port=Port,
		     server_ip=Host,
		     server_key=SKey,
		     client_key=CKey,
		     client_count = irand64(),
		     reconnect_interval=Reconnect_i,
		     ping_interval=Ping_i,
		     auth_timeout = Auth_t,
		     topic_list = TopicList
		   }).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call({sub,Topic}, From, State) ->
    remote_call({sub,[Topic]}, From, State);
handle_call({unsub,Topic}, From, State) ->
    remote_call({unsub,[Topic]}, From, State);
handle_call(Request={pub,_Topic,_Value}, From, State) ->
    remote_call(Request, From, State);
handle_call(Request={pub,_Topic,_Value,_TimeStamp}, From, State) ->
    remote_call(Request, From, State);
handle_call(_Request, _From, State) ->
    {reply, {error,bad_call}, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------

handle_info({Tag,Socket,<<Hash:?HSIZE/binary,Count:?CSIZE,Bin/binary>>},
	    State=#state {socket = S}) when 
      (Tag =:= tcp orelse Tag =:= ssl), 
      Socket =:= S#exo_socket.socket ->
    lager:debug("got data hash=~w, data=~p", [Hash,Bin]),
    exo_socket:setopts(S, [{active, once}]),
    try binary_to_term(Bin) of
	Mesg={auth_res,_} when State#state.state =:= auth ->
	    case verify(State#state{server_count=Count},Hash,Count,Bin) of
		{ok,State1} ->
		    handle_auth_res(Mesg,State1);
		Error ->
		    lager:error("message error ~p mesg ~p", [Error,Mesg]),
		    {stop,Error,State}
	    end;
	Mesg ->
	    case verify(State,Hash,Count,Bin) of
		{ok,State1} ->
		    case Mesg of
			{xbus,_TopicPattern,#{ topic:=Topic,
					       value:=Value,
					       timestamp:=TimeStamp }} ->
			    handle_xbus(Topic,Value,TimeStamp,State1),
			    {noreply, State1};
			{reply,ID,Reply} ->
			    case lists:keytake(ID,2,State1#state.wait_recv) of
				false ->
				    {noreply,State1};
				{value,{From,ID,{call,ID,_Request}},Wr} ->
				    gen_server:reply(From, Reply),
				    {noreply,State1#state { wait_recv = Wr}}
			    end;
			ping_res ->
			    {noreply,State1#state { ping_response = true }};
			Term ->
			    lager:warning("got unhandled term ~p", [Term]),
			    {noreply, State1}
		    end;
		Error ->
		    lager:error("message error ~p mesg ~p", [Error,Mesg]),
		    {stop,Error,State}
	    end
    catch
	error:Reason ->
	    lager:warning("got bad data ~p", [{error,Reason}]),
	    {noreply, State}
    end;
handle_info({Tag,Socket}, State) when
      (Tag =:= tcp_closed orelse Tag =:= ssl_closed),
      Socket =:= (State#state.socket)#exo_socket.socket ->
    lager:debug("got tag ~p", [{Tag,Socket}]),
    State1 = close(State),
    {ok,State2} = connect_later(State1),
    {noreply, State2};

handle_info({timeout,TRef,reconnect}, State)
  when State#state.reconnect_timer =:= TRef ->
    case connect(State#state { reconnect_timer = undefined }) of
	{ok,State1} ->
	    {noreply, State1};
	{stop,Error} ->
	    {stop,Error,State}
    end;

handle_info({timeout,TRef,ping}, State)
  when State#state.ping_timer =:= TRef ->
    if State#state.state =:= open,
       State#state.ping_response =:= true ->
	    Timer = start_timer(State#state.ping_interval, ping),
	    State1 = State#state { ping_timer = Timer,
				   ping_response = false,
				   ping_count = State#state.server_count },
	    lager:debug("send ping", []),
	    State2 = send(State1, ping),
	    {noreply, State2};
       State#state.state =:= open ->
	    %% no ping response / message from server, disconnect and reopen
	    lager:debug("no ping response closing", []),
	    State1 = close(State),
	    {ok,State2} = connect_later(State1),
	    {noreply, State2};
       true ->
	    {noreply, State}
    end;

handle_info({timeout,TRef,auth}, State)
  when State#state.auth_timer =:= TRef ->
    lager:warning("auth timeout", []),
    State1 = close(State),
    case connect(State1#state { auth_timer = undefined }) of
	{ok,State1} ->
	    {noreply, State1};
	{stop,Error} ->
	    {stop,Error,State}
    end;
handle_info(_Info, State) ->
    io:format("GOT INFO = ~p\n", [_Info]),
    lager:debug("got info ~p", [_Info]),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, State) ->
    close(State),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% handle META messages by removing persistent and retain attributes
handle_xbus(<<"{META}.",Topic/binary>>, Value, _TimeStamp, _State) ->
    MetaOld = xbus:read_meta(Topic),
    MetaNew = meta_remove([persistent, retain], Value),
    Meta = meta_merge(MetaOld, MetaNew),
    xbus:pub_meta(Topic, Meta);
%% FIXME: handle timestamp diff
handle_xbus(Topic, Value, TimeStamp, State) ->
    TimeStamp1 = TimeStamp + State#state.timediff,
    xbus:pub(Topic, Value, TimeStamp1).

%% fixme: handle timestamp and client server time diff
handle_auth_res(_Mesg={auth_res,#{id:=ServerName,
				  %% timestamp := ServerTs,
				  chal:=Chal,
				  cred:=Cred}}, State) ->
    lager:debug("auth_res: ~p ok", [_Mesg]),
    case crypto:hash(sha,[State#state.server_key,State#state.chal]) of
	Cred ->
	    lager:info("client ~p credential accepted by server ~p", 
		       [State#state.name, ServerName]),
	    stop_timer(State#state.auth_timer),
	    Timer = start_timer(State#state.ping_interval, ping),
	    Cred1 = crypto:hash(sha,[State#state.client_key,Chal]),
	    State1 = send(State,{auth_ack,#{id=>State#state.id,cred=>Cred1}}),
	    State2 = State1#state { auth_timer = undefined,
				    ping_timer = Timer,
				    ping_response = true,
				    ping_count = State#state.server_count,
				    server_name = ServerName,
				    state = open
				    %% timediff = xbus:timestamp() - ServerTs
				  },
	    State3 = transmit_wait(State2),
	    {noreply, State3};
	_CredFail ->
	    lager:debug("credential failed"),
	    State1 = close(State),
	    State2 = connect_later(State1),
	    {noreply, State2}
    end.
    
remote_call(Request, From, State) ->
    ID = make_ref(),
    if State#state.state =:= open ->
	    State1 = send(State,{call,ID,Request}),
	    Wr = [{From,ID,{call,ID,Request}}|State1#state.wait_recv],
	    {noreply, State1#state { wait_recv = Wr }};
       true ->
	    %% fixme monitor!
	    Ws = State#state.wait_send++[{From,ID,{call,ID,Request}}],
	    {noreply, State#state { wait_send = Ws }}
    end.

%% Emit calls/casts/info when socket is connected
transmit_wait(State) ->
    transmit_wait_(State,State#state.wait_send,
		   State#state.wait_recv).

transmit_wait_(State, [W={_From,ID,{call,ID,Request}}|Ws], Wr) ->
    State1 = send(State, {call,ID,Request}),
    transmit_wait_(State1, Ws, [W|Wr]);
transmit_wait_(State, [], Wr) ->
    State#state { wait_send = [], wait_recv = Wr }.

send(State, Message) ->
    Bin    = term_to_binary(Message),
    Count  = State#state.client_count,
    Hash   = crypto:hash(sha,[State#state.client_key,<<Count:64>>,Bin]),
    lager:debug("send: HASH ckey=~p ~p ~p = ~p",
		[State#state.client_key,Count,Bin,Hash]),
    Packet = <<Hash:?HSIZE/binary,Count:?CSIZE,Bin/binary>>,
    ok = exo_socket:send(State#state.socket, Packet),
    State#state { client_count = Count + 1}.

verify(State,Hash,Count,Bin) ->
    if State#state.server_count =:= Count ->
	    Hash1 = crypto:hash(sha,[State#state.server_key,<<Count:64>>,Bin]),
	    if Hash1 =:= Hash ->
		    {ok,State#state { server_count = Count+1 }};
	       true ->
		    lager:error("verify: HASH skey=~p ~p ~p = ~p (expect ~p)", 
				[State#state.server_key,Count,Bin,Hash1,Hash]),
		    {error,bad_signature}
	    end;
       true ->
	    lager:error("verify: Count=~w, expected=~w",
			[Count, State#state.server_count]),
	    {error, bad_count}
    end.

meta_remove([P|Ps], Meta) when is_list(Meta) ->
    meta_remove(Ps, proplists:delete(P, Meta));
meta_remove([], Meta) when is_list(Meta) ->
    Meta;
meta_remove(Ps, Meta) when is_map(Meta) ->
    maps:with(maps:keys(Meta) -- Ps, Meta).

meta_merge(OldMeta, [{P,V}|NewMeta]) ->
    meta_merge([{P,V}|proplists:delete(P, OldMeta)],NewMeta);
meta_merge(OldMeta, []) ->
    OldMeta;
meta_merge(OldMeta, NewMeta) when is_map(OldMeta), is_map(NewMeta) ->
    maps:merge(OldMeta, NewMeta).

irand64() ->
    <<R:64>> = crypto:strong_rand_bytes(8),
    R.

key(Key) when is_integer(Key) -> <<Key:64>>;
key(Key) when is_binary(Key) ->  Key;
key(Key) when is_list(Key) ->    iolist_to_binary(Key);
key(Key) when is_atom(Key) ->    atom_to_binary(Key,latin1).

close(State) ->
    stop_timer(State#state.auth_timer),
    stop_timer(State#state.reconnect_timer),
    stop_timer(State#state.ping_timer),
    if State#state.socket =:= undefined -> ok;
       true -> exo_socket:close(State#state.socket)
    end,
    State#state { state=closed, socket = undefined,
		  auth_timer = undefined,
		  reconnect_timer = undefined,
		  ping_timer = undefined }.

connect(State) ->
    case exo_socket:connect(State#state.server_ip, State#state.server_port,
			    [tcp], [{active,once},{mode,binary}, {packet,4},
				    {nodelay, true}], 
			    ?DEFAULT_CONNECT_TIMEOUT) of
	{ok,Socket} ->
	    Chal  = crypto:strong_rand_bytes(16),
	    Timer = start_timer(State#state.auth_timeout, auth),
	    Ws0   = State#state.wait_send,
	    Ws = if State#state.topic_list =:= [] -> Ws0;
		    true ->
			 %% Maybe separate in sub and sub_meta?
			 TL = lists:append([[T,<<"{META}.",T/binary>>] || 
					       T <- State#state.topic_list]),
			 CRef = make_ref(),
			 From = {self(),CRef},
			 Call = {call,CRef,{sub,TL}},
			 Ws0++[{From,CRef,Call}]
		 end,
	    State1 = State#state { socket=Socket, 
				   state = auth,
				   auth_timer = Timer,
				   chal = Chal,
				   wait_send = Ws },
	    State2 = send(State1,{auth_req,
				  #{ id=>State#state.id,
				     chal=>Chal,
				     timestamp=>xbus:timestamp()}}),
	    {ok,State2};
	{error,nxdomain} ->      connect_later(State);
	{error,econnrefused} ->  connect_later(State);
	{error,timeout} ->       connect_later(State);
	{error,Reason} -> {stop,{error,Reason}}
    end.

connect_later(State) ->
    if State#state.reconnect_interval =:= infinity ->
	    {stop, {error,timeout}};
       is_integer(State#state.reconnect_interval), 
       State#state.reconnect_interval > 0 ->
	    Tmo = max(1000,State#state.reconnect_interval), 
	    Timer = start_timer(Tmo, reconnect),
	    {ok, State#state { reconnect_timer = Timer }};
       true ->
	    {stop, {error,einval}}
    end.

stop_timer(undefined) ->	    
    undefined;
stop_timer(TRef) ->
    erlang:cancel_timer(TRef),
    receive
	{timeout,TRef,_} ->
	    undefined
    after 0 ->
	    undefined
    end.

start_timer(Tmo, Kind) ->
    erlang:start_timer(Tmo, self(), Kind).
