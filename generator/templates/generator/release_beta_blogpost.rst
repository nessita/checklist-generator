Django {{ final_version }} beta 1 is now available. It represents the second
stage in the {{ final_version }} release cycle and is an opportunity for you to
try out the changes coming in Django {{ final_version }}.

Django {{ final_version }} brings {{ instance.feature_release.tagline }} which
you can read about in `the in-development {{ final_version }} release notes
<https://docs.djangoproject.com/en/dev/releases/{{ final_version }}/>`_.

Only bugs in new features and regressions from earlier versions of Django will
be fixed between now and the {{ final_version }} final release. Translations will be updated
following the "string freeze", which occurs when the release candidate is
issued. The `current release schedule
<https://code.djangoproject.com/wiki/Version{{ final_version }}Roadmap#schedule>`_ calls for a
release candidate in a month from now, and a final release to follow about two
weeks after that, scheduled for {{ instance.feature_release.when|date:"F j" }}.

Early and frequent testing from the community will help minimize the number of
bugs in the release. Updates on the release schedule are available `on the
Django forum <{{ instance.feature_release.forum_post }}>`_.

As with all alpha and beta packages, this is **not** for production use. But if
you'd like to take some of the new features for a spin, or to help find and fix
bugs (which should be reported to `the issue tracker
<https://code.djangoproject.com/newticket>`_), you can grab a copy of the beta
package from `our downloads page <https://www.djangoproject.com/download/>`_ or
on PyPI.

{% include "generator/_relaser_info.rst" %}
