# Hawken API

Hawken API is a Python 3.x library to interface with the Hawken Client API. It also supports working with Hawken's custom XMPP extensions, by way of SleekXMPP plugin. Development on the library started in 2013 and ended in 2017.

## Disclaimers

This library is released as-is. While the client calls are abstracted, the data format is completely undocumented (to an extent, the API is data-agnostic itself). The point of the release is really to show the work I put into this, as up until the publishing of this it's been private.
 
All the code in this library as it stands today was developed solely via reverse engineering using packet captures, probing of the Hawken API server, and guesswork. No internal knowledge is included within or used by this repo's code.
 
_It is to be noted that due to prior inclusion of a tiny bit of proprietary code (seriously, it was exceedingly trivial, but better safe than sorry), everything after 0.6.2.1 was rebased and force-pushed. The original authored dates are still in place (where relevant). Some minor commit reordering was also done to split off the bulk of 0.8 changes from 0.7 bugfixes._

## History

This is the third or so revision of my Hawken API client library. Previous ones were hacky and/or incomplete. For this iteration, a very strong effort was made to fully implement the client API, regardless of usefulness (see VOIP API calls). A secondary objective was to merge codebases between what I and [another developer](https://github.com/Zren) were using at the time.

In the end, the following projects ended up using this library:

- [Hawken Scrimbot](https://github.com/ashfire908/hawken-scrimbot)
- [Hawken Tracker](https://github.com/ashfire908/hawken-tracker)
- Hawken Tools (never released, now dead)
- [Hawken Stats](http://tools.ashfire908.com/hwkcharts/)
- [Zren](https://github.com/Zren)'s set of Hawken server listing and tools (better known as "the Heroku app")
- Probably various other scripts

Updates were made over time to the repo to keep up with Hawken's API. Development of the library stopped in 2017. Now that it's been a few years since it was shut down on PC, and that this library never worked with the console ports, I am open sourcing this project.

## Features

The library covers every known API the client touches, plus some one can discover by guessing (eg if an endpoint is `/items/guid`, trying `/items/` or `/items`, or different HTTP methods), assuming said endpoint accepts a client access grant.

It also includes a Redis-backed caching layer, and provides a SleekXMPP module for Hawken's custom XMPP extensions (see [Scrimbot](https://github.com/ashfire908/hawken-scrimbot) for an example).

## Usage

I don't really know what you'd use this for these days (I'm publishing this just to show my work at this point), but if you make use of it, some things to know:

- Under Reloaded Games, a revamp of the API was performed. These changes were incorporated into the library in version 0.8 and later. Versions prior to 0.8 do not use these updated APIs.
- I didn't and still don't know how to generate a steam auth token. At the time, I just stole them from the game client on submission to the server. All real use of the library was via the storm user/pass auth.

## License

Hawken API is released under the [MIT LICENSE](LICENSE).
