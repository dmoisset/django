from __future__ import unicode_literals

import logging
from functools import update_wrapper
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Type

from django import http
from django.core.exceptions import ImproperlyConfigured
from django.template.response import TemplateResponse
from django.urls import NoReverseMatch, reverse
from django.utils import six
from django.utils.decorators import classonlymethod

logger = logging.getLogger('django.request')


class ContextMixin(object):
    """
    A default context mixin that passes the keyword arguments received by
    get_context_data as the template context.
    """

    def get_context_data(self, **kwargs: object) -> Dict[str, object]:
        if 'view' not in kwargs:
            kwargs['view'] = self
        return kwargs


class View(object):
    """
    Intentionally simple parent class for all views. Only implements
    dispatch-by-method and simple sanity checking.
    """

    http_method_names = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace']

    request = None  # type: http.HttpRequest
    args = None  # type: Tuple[object, ...]
    kwargs = None  # type: Dict[str, object]
    del request, args, kwargs  # definitions above just added for mypy

    def __init__(self, **kwargs: object) -> None:
        """
        Constructor. Called in the URLconf; can contain helpful extra
        keyword arguments, and other things.
        """
        # Go through keyword arguments, and either save their values to our
        # instance, or raise an error.
        for key, value in six.iteritems(kwargs):
            setattr(self, key, value)

    @classonlymethod
    def as_view(cls, **initkwargs: object) -> Callable[..., http.HttpResponse]:
        """
        Main entry point for a request-response process.
        """
        for key in initkwargs:
            if key in cls.http_method_names:
                raise TypeError("You tried to pass in the %s method name as a "
                                "keyword argument to %s(). Don't do that."
                                % (key, cls.__name__))  # type: ignore
            if not hasattr(cls, key):
                raise TypeError("%s() received an invalid keyword %r. as_view "
                                "only accepts arguments that are already "
                                "attributes of the class." % (cls.__name__, key))  # type: ignore

        def view(request: http.HttpRequest, *args: object, **kwargs: object) -> http.HttpResponse:
            self = cls(**initkwargs)  # type: ignore  # mypy doesn't know this is a classmethod
            if hasattr(self, 'get') and not hasattr(self, 'head'):
                self.head = self.get
            self.request = request
            self.args = args
            self.kwargs = kwargs
            return self.dispatch(request, *args, **kwargs)
        view.view_class = cls  # type: ignore
        view.view_initkwargs = initkwargs  # type: ignore

        # take name and docstring from class
        update_wrapper(view, cls, updated=())  # type: ignore  # mypy believes cls to be a view instance

        # and possible attributes set by decorators
        # like csrf_exempt from dispatch
        update_wrapper(view, cls.dispatch, assigned=())
        return view

    def dispatch(self, request: http.HttpRequest, *args: object, **kwargs: object) -> http.HttpResponse:
        # Try to dispatch to the right method; if a method doesn't exist,
        # defer to the error handler. Also defer to the error handler if the
        # request method isn't on the approved list.
        if request.method.lower() in self.http_method_names:
            handler = getattr(self, request.method.lower(), self.http_method_not_allowed)
        else:
            handler = self.http_method_not_allowed
        return handler(request, *args, **kwargs)

    def http_method_not_allowed(self, request: http.HttpRequest, *args: object, **kwargs: object) -> http.HttpResponse:
        logger.warning(
            'Method Not Allowed (%s): %s', request.method, request.path,
            extra={'status_code': 405, 'request': request}
        )
        return http.HttpResponseNotAllowed(self._allowed_methods())

    def options(self, request: http.HttpRequest, *args: object, **kwargs: object) -> http.HttpResponse:
        """
        Handles responding to requests for the OPTIONS HTTP verb.
        """
        response = http.HttpResponse()
        response['Allow'] = ', '.join(self._allowed_methods())
        response['Content-Length'] = '0'
        return response

    def _allowed_methods(self) -> List[str]:
        return [m.upper() for m in self.http_method_names if hasattr(self, m)]


class TemplateResponseMixin(object):
    """
    A mixin that can be used to render a template.
    """
    template_name = None  # type: str
    template_engine = None  # type: Optional[str]
    response_class = TemplateResponse  # type: Type[http.HttpResponse]
    content_type = None  # type: Optional[str]

    request = None  # type: http.HttpRequest

    def render_to_response(self, context: Dict[str, object], **response_kwargs: object) -> http.HttpResponse:
        """
        Returns a response, using the `response_class` for this
        view, with a template rendered with the given context.

        If any keyword arguments are provided, they will be
        passed to the constructor of the response class.
        """
        response_kwargs.setdefault('content_type', self.content_type)
        return self.response_class(
            request=self.request,
            template=self.get_template_names(),
            context=context,
            using=self.template_engine,
            **response_kwargs
        )

    def get_template_names(self) -> List[str]:
        """
        Returns a list of template names to be used for the request. Must return
        a list. May not be called if render_to_response is overridden.
        """
        if self.template_name is None:
            raise ImproperlyConfigured(
                "TemplateResponseMixin requires either a definition of "
                "'template_name' or an implementation of 'get_template_names()'")
        else:
            return [self.template_name]


class TemplateView(TemplateResponseMixin, ContextMixin, View):
    """
    A view that renders a template.  This view will also pass into the context
    any keyword arguments passed by the URLconf.
    """
    def get(self, request: http.HttpRequest, *args: object, **kwargs: object) -> http.HttpResponse:
        context = self.get_context_data(**kwargs)
        return self.render_to_response(context)


class RedirectView(View):
    """
    A view that provides a redirect on any GET request.
    """
    permanent = False
    url = None  # type: Optional[str]
    pattern_name = None  # type: Optional[str]
    query_string = False

    def get_redirect_url(self, *args: object, **kwargs: object) -> Optional[str]:
        """
        Return the URL redirect to. Keyword arguments from the
        URL pattern match generating the redirect request
        are provided as kwargs to this method.
        """
        if self.url:
            url = self.url % kwargs
        elif self.pattern_name:
            try:
                url = reverse(self.pattern_name, args=args, kwargs=kwargs)
            except NoReverseMatch:
                return None
        else:
            return None

        args = self.request.META.get('QUERY_STRING', '')
        if args and self.query_string:
            url = "%s?%s" % (url, args)
        return url

    def get(self, request: http.HttpRequest, *args: object, **kwargs: object) -> http.HttpResponse:
        url = self.get_redirect_url(*args, **kwargs)
        if url:
            if self.permanent:
                return http.HttpResponsePermanentRedirect(url)
            else:
                return http.HttpResponseRedirect(url)
        else:
            logger.warning(
                'Gone: %s', request.path,
                extra={'status_code': 410, 'request': request}
            )
            return http.HttpResponseGone()

    def head(self, request: http.HttpRequest, *args: object, **kwargs: object) -> http.HttpResponse:
        return self.get(request, *args, **kwargs)

    def post(self, request: http.HttpRequest, *args: object, **kwargs: object) -> http.HttpResponse:
        return self.get(request, *args, **kwargs)

    def options(self, request: http.HttpRequest, *args: object, **kwargs: object) -> http.HttpResponse:
        return self.get(request, *args, **kwargs)

    def delete(self, request: http.HttpRequest, *args: object, **kwargs: object) -> http.HttpResponse:
        return self.get(request, *args, **kwargs)

    def put(self, request: http.HttpRequest, *args: object, **kwargs: object) -> http.HttpResponse:
        return self.get(request, *args, **kwargs)

    def patch(self, request: http.HttpRequest, *args: object, **kwargs: object) -> http.HttpResponse:
        return self.get(request, *args, **kwargs)
