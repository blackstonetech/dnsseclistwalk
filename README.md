DNSSECListWalk
==============

**DNSSECListWalk** takes a list of domains and determines their DNSSEC status.

History
=======

The original script was written by Scott Rose of NIST.
Richard Bullington-McGuire <rbullington-mcguire@bstonetech.com>, 
also known as @obscurerichard, adapted it for release at the 2011 1.USA.gov
Hack Day on July 29, 2011.

Environment
===========

This script requires Perl 5 and two Perl modules from CPAN [1]: 

* Mail::Sendmail
* Net::DNS

You may install those into your system Perl installation using CPAN [1], or do use
local::lib [2] and cpanminus [3] to install those into a non-root user
directory, as current Perl best practices [4] suggest. If you have cpanminus
installed you need only issue this command:

    cpanm Mail::Sendmail Net::DNS

See one of the many tutorial introductions to installing Perl modules as
a non-root user [5] [6] for more information on setting this up.

References
==========

  [1] http://www.cpan.org/
  [2] http://search.cpan.org/~apeiron/local-lib-1.008004/lib/local/lib.pm
  [3] http://search.cpan.org/~miyagawa/App-cpanminus-1.4008/lib/App/cpanminus.pm
  [4] http://search.cpan.org/~apeiron/Task-Kensho-0.31/lib/Task/Kensho.pm
  [5] http://perl.jonallen.info/writing/articles/install-perl-modules-without-root
  [6] http://blogs.perl.org/users/peter_edwards/2011/06/installing-local-perl-and-libraries-on-mac-book-snow-leopard.html


Licence
=======

(The MIT License)

Copyright © 2011 Blackstone Technology Group

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the ‘Software’), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED ‘AS IS’, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
