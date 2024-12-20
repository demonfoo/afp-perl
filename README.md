### Net::AFP version 0.69

This collection of modules implements the Apple Filing Protocol stack in
Perl. It contains several separate modules which implement components
that allow it to do its work:

* Net::DSI - A Perl implementation of the DSI mid-layer protocol over TCP
* Net::AFP - A superclass implementing generic AFP operations
* Net::AFP::TCP - A derivative of Net::AFP implementing TCP transport
* Net::AFP::Atalk - A derivative of Net::AFP implementing AppleTalk transport
* Fuse::AFP - A derivative of Fuse::Class implementing a Fuse filesystem
* Net::AFP::UAMs - A utility module for calling [User Authentication Methods](https://developer.apple.com/library/mac/documentation/Networking/Conceptual/AFP/AFPSecurity/AFPSecurity.html#//apple_ref/doc/uid/TP40000854-CH232-CHBCEJBD)
* Net::AFP::Versions - A utility module for protocol [version](https://developer.apple.com/library/mac/documentation/Networking/Reference/AFP_Reference/index.html#//apple_ref/doc/constant_group/AFP_Version_Strings) agreement and checking
* Net::AFP::ACL - A package providing symbols related to using AFP's [Access Control List](https://developer.apple.com/library/mac/documentation/Networking/Conceptual/AFP/AFPSecurity/AFPSecurity.html#//apple_ref/doc/uid/TP40000854-CH232-CHDGEHBB) implementation
* Net::AFP::Result - Symbols for known AFP result codes, and mappings of [result codes](https://developer.apple.com/library/mac/documentation/Networking/Reference/AFP_Reference/index.html#//apple_ref/doc/uid/TP40003548-CH6-SW1) to error strings
* Net::AFP::Parsers - A utility module for parsing various common packed data types and structures from an AFP server

This code is known to work on Linux, [FreeBSD](http://www.freebsd.org) (8.x), [NetBSD](http://www.netbsd.org) and [MacOS X](http://www.apple.com/osx/)/Darwin.
It makes use of Perl ithreads, so requires a threaded build of Perl.
I have attempted to test this module on Windows; unfortunately there seem
to be threading deficiencies on Windows that make the code non-functional
there.

More information is available on AFP [here](http://developer.apple.com/library/mac/#documentation/Networking/Conceptual/AFP/Introduction/Introduction.html).


#### INSTALLATION

To install this module, run the following:

```bash
perl Makefile.PL
make
make install
```


#### DEPENDENCIES

This module requires or encourages use of these other modules and libraries:

* [Log::Log4perl](https://metacpan.org/pod/Log::Log4perl) is used for some message logging
* [Log::Dispatch::Syslog](https://metacpan.org/pod/Log::Dispatch::Syslog) is used for routing log messages to syslog
* [Fuse::Class](https://metacpan.org/pod/Fuse::Class) is used as the superclass for Fuse::AFP
* [Fuse](https://metacpan.org/pod/Fuse) is depended upon by Fuse::Class, need version 0.10\_1 or later
* [String::Escape](https://metacpan.org/pod/String::Escape) is required for Fuse::AFP and *afpmount.pl*
* [UUID](https://metacpan.org/pod/UUID) is recommended, used internally for access checking
* [CryptX](https://metacpan.org/pod/CryptX) is strongly recommended; all UAMs other than plaintext need it
* [IO::Socket::IP](https://metacpan.org/pod/IO::Socket::IP) is recommended, adds v6 socket support
* [Net::Atalk](https://github.com/demonfoo/atalk-perl) is suggested, adds AppleTalk socket support
* [Net::Bonjour](https://metacpan.org/pod/Net::Bonjour) is suggested, adds mDNS/Bonjour service discovery
* [Term::ReadPassword](https://metacpan.org/pod/Term::ReadPassword) is recommended
* [Readonly](https://metacpan.org/pod/Readonly) is required
* [Params::Validate](https://metacpan.org/pod/Params::Validate) is required
* [Term::ReadLine](https://metacpan.org/pod/Term::ReadLine) is required for *afpclient.pl*; [Term::ReadLine::Gnu](https://metacpan.org/pod/Term::ReadLine::Gnu) or
  [Term::ReadLine::Perl5](https://metacpan.org/pod/Term::ReadLine::Perl5) is recommended
* [PerlIO::buffersize](https://metacpan.org/pod/PerlIO::buffersize) is recommended for *afpmount.pl*
* [URI::Escape](https://metacpan.org/pod/URI::Escape) is required for Fuse::AFP and *afpmount.pl*
* [Class::InsideOut](https://metacpan.org/pod/Class::InsideOut) is required
* [Text::Glob](https://metacpan.org/pod/Text::Glob) is required for *afpclient.pl*


#### FREQUENTLY ASKED QUESTIONS

Q: What is this useful for?

A: If you have a Macintosh computer, or Apple hardware (like an Apple AirPort Extreme with AirPort Disk), and want to share files with the device, you can use these tools to do so. Also, it's kind of fun to have a filesystem where you can run the code, and still see how it's implemented.


Q: Why not just use Samba?

A: You could, but Samba is slower; the Samba developers have made the best of a not-so-great protocol, but these systems speak AFP natively and so do a better job.


Q: It's not even version 1.0 yet? Why should I use this if you don't even think it's "version 1.0" material?

A: There are a few things I want to get in before I make it 1.0, but it's a pretty stable piece of code, which I use every day now. Really, it (probably) won't bite.


Q: I mounted my filesystem and put my computer to sleep, or did something else, and now when I try to access the mounted filesystem, I get a message that says "Transport endpoint is not connected". What is wrong?

A: This is the Fuse layer telling you that the program has gone away; if you put your computer to sleep, that happens because the AFP server got bored of waiting for us to talk to it again, and disconnected. Sleeping is not yet handled correctly. If you didn't put your computer to sleep, and got this or "Software caused connection abort", then you may have found a bug. I think I've nailed most of them, but it's always possible. Let me know what you did.


Q: UNIX permissions show up in 'ls'/Nautilus/... but don't seem to have any real effect. Why?

A: Because the permissions you see are relevant to our login to the server (obvious exception: the execute bit), but not really to the local system. It's complicated, since multiple layers of authentication are involved.


Q: Extended attribute names are different on Linux than on OS X. What's the deal?

A: Linux (and most other UN\*X-ish OSes) have a fairly simple view of extended attribute namespaces: There's 'user.\*', which are attributes which can be manipulated and viewed directly by users, and 'system.\*', which are special and are meant to be seen only by system tools (like the extended attributes that ACLs use). Since most OSes' idea of how things work is a bit different from OS X's, we have to make things fit, so OS X's user-visible EAs are prefixed with 'user.' to make it fit better. If you don't like it, tell me why; better yet, tell me why and send a patch to make things work in your more-sensible way.


Q: Why don't getfacl/setfacl work on an AFP filesystem?

A: Well, that's because I said AFP supports ACLs. I didn't say what kind.  Unfortunately, there are a couple different ACL models floating around out there; there's the POSIX ACL model which Linux and FreeBSD co-opted awhile back, which is better than basic UNIX permissions since it can be applied to multiple users/groups without hacks like making a huge group to encompass all the users relevant to that one file. Then, there's the NFSv4/Solaris/Windows/OS X/AFP style ACL, which is of course entirely different. It adds finer-grained controls (read, list, write, add\_file, execute, search, delete, append, add\_subdirectory, and so on), as well as rules that both confer _and_ eliminate specific operational permissions. The models are, needless to say, not 1:1, so POSIX ACL tools are basically useless. That's what the 'afp\_acl.pl' tool is for; it lets you view the ACL on a file, add/delete/modify entries, clear ACLs, you know.


Q: I have an AirPort Disk device mounted. All files have 0777 permissions, and ACLs don't work. What's the deal?

A: AirPort Disk devices provide UNIX permission bits, but don't actually support changing permissions, and they don't set the "I know ACLs" flag in the volume metadata. If you think they should support these features, complain to Apple. Also, it's the same deal with OS X, so it's not like I'm doing something to disable a feature that works with Apple's client.


Q: Why is it slow?

A: My experience has shown that it's actually pretty fast in general. Reading files can easily peak at 200-300 Mbps on a fast medium (e.g.: gigabit Ethernet, IP-over-FireWire network), and pretty much complete connection saturation on 100 Mbps Ethernet. Directory walking is somewhat slower than with Apple's client, but not very much (about half as fast). If you're seeing substantially lower performance, check your network driver's poll rate and events per interrupt parameters.


Q: What operating systems does this crazy thing work on?

A: I have successfully run this code on Linux 2.6-based distributions (specifically Ubuntu 9.10 and later, Fedora 14, and Debian), FreeBSD 8.1, NetBSD 5.x, and Mac OS X 10.4 and later with MacFUSE. (FreeBSD requires a customized Perl build with threads support.)

I did successfully use it with NetBSD 4.x, but PUFFS/ReFUSE wasn't yet integrated with the distribution, which made it very difficult to set up; NetBSD 5.x includes PUFFS, so I would recommend using it.

Older versions of FreeBSD suffered problems with Perl threads, mostly when unmounting filesystems. I know FreeBSD 8.1 definitely works cleanly.

I have tried to get this code to work on Solaris (specifically  Nexenta) and Windows; unfortunately it seems that Perl threads do not work so well on these platforms. Windows has some odd interaction between sockets and threads, causing socket writes to block for longer and longer before sending for no obvious reason, and on Nexenta it just dies as soon as I start trying to use threads, no errors, just insta-death. If you try this on another platform with success, let me know.


Q: How much are you having to cheat to make the performance be... well, not terrible?

A: Really, less than you'd think. I used to have extensive metadata caching, but once the DSI layer's performance became decent, that was mostly unnecessary. I recommend mounting with '-o big\_writes', to support the use of large write block sizes (up to 128 KB per write) with FUSE; this substantially speeds up writes.


Q: I tried the open-source Jaffer AFP file server, and it doesn't work right with your client! What's the problem?

A: The author of Jaffer is no longer maintaining his code. Even when he was, his implementation was pretty broken, completely ignoring the proper syntax for several calls, particularly certain fork state get/set operations. He even says that mounting an export provided by Jaffer can, and has been known to, crash Finder on OS X. So no, the fact that his "AFP server" code is broken is **not** a reflection on my code; I've been as careful as possible in following the AFP specifications provided by Apple.


#### COPYRIGHT AND LICENSE

Copyright © 2005-2016 Derrik Pates


