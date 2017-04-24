-module(exobus_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

%% Helper macro for declaring children of supervisor
-define(CHILD(Id,Mod,Type,As), {Id,{Mod,start_link,[As]},
				permanent,5000,Type,[Mod]}).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    Cs = case application:get_env(exobus, mode) of
	     {ok,client} ->
		 {ok,Servers} = application:get_env(exobus, servers),
		 [?CHILD(Name,exobus_cli, worker, [{name,Name}]) || 
		     {Name,_Opts} <- Servers];
	     {ok,server} ->
		 {ok,ID} = application:get_env(exobus, id),
		 [?CHILD(ID,exobus_srv, worker, [])]
	 end,
    {ok, { {one_for_one, 5, 10}, Cs} }.
