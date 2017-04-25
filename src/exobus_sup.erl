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
    Cs1 = case application:get_env(exobus, clients) of
	      undefined -> [];
	      {ok,[]} -> [];
	      {ok,_Clients} ->
		  {ok,ID} = application:get_env(exobus, id),
		  [?CHILD(ID,exobus_srv, worker, [])]
	  end,
    Cs2 = case application:get_env(exobus, servers) of
	      undefined -> [];
	      {ok,[]} -> [];
	      {ok,Servers} ->
		  [?CHILD(Name,exobus_cli, worker, [{name,Name}]) || 
		      {Name,_Opts} <- Servers]
	  end,
    {ok, { {one_for_one, 5, 10}, Cs1++Cs2} }.
