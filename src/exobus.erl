%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2017, Tony Rogvall
%%% @doc
%%%    start / stop
%%% @end
%%% Created : 21 Apr 2017 by Tony Rogvall <tony@rogvall.se>

-module(exobus).

-export([start/0, stop/0]).

start() ->
    application:ensure_all_started(exobus).

stop() ->
    application:stop(exobus).
