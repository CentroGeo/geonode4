#########################################################################
#
# Copyright (C) 2016 OSGeo
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#########################################################################
from django.db.models import Q
from tastypie.authentication import ApiKeyAuthentication
from tastypie.authorization import DjangoAuthorization
from tastypie.exceptions import Unauthorized
from tastypie.compat import get_user_model, get_username_field

from rest_framework import authentication

from guardian.shortcuts import get_objects_for_user
from tastypie.http import HttpUnauthorized

from django.conf import settings

from geonode import geoserver
from geonode.utils import check_ogc_backend

from datetime import datetime, timedelta, timezone

class GeoNodeAuthorization(DjangoAuthorization):
    """Object level API authorization based on GeoNode granular
    permission system"""

    def read_list(self, object_list, bundle):
        permitted_ids = []
        try:
            permitted_ids = get_objects_for_user(bundle.request.user, "base.view_resourcebase").values("id")
        except Exception:
            pass

        return object_list.filter(id__in=permitted_ids)

    def read_detail(self, object_list, bundle):
        if "schema" in bundle.request.path:
            return True
        return bundle.request.user.has_perm("view_resourcebase", bundle.obj.get_self_resource())

    def create_list(self, object_list, bundle):
        # TODO implement if needed
        raise Unauthorized()

    def create_detail(self, object_list, bundle):
        return bundle.request.user.has_perm("add_resourcebase", bundle.obj.get_self_resource())

    def update_list(self, object_list, bundle):
        # TODO implement if needed
        raise Unauthorized()

    def update_detail(self, object_list, bundle):
        return bundle.request.user.has_perm("change_resourcebase", bundle.obj.get_self_resource())

    def delete_list(self, object_list, bundle):
        # TODO implement if needed
        raise Unauthorized()

    def delete_detail(self, object_list, bundle):
        return bundle.request.user.has_perm("delete_resourcebase", bundle.obj.get_self_resource())


class GeonodeApiKeyAuthentication(ApiKeyAuthentication):
    """
    Override ApiKeyAuthentication to prevent 401 response when no api key is provided.
    """

    def is_authenticated(self, request, **kwargs):
        """
        Finds the user and checks their API key.

        Should return either ``True`` if allowed, ``False`` if not or an
        ``HttpResponse`` if you need something custom.
        """

        try:
            username, api_key = self.extract_credentials(request)
        except ValueError:
            return self._unauthorized()

        if not username or not api_key:
            return True

        username_field = get_username_field()
        User = get_user_model()

        try:
            lookup_kwargs = {username_field: username}
            user = User.objects.get(**lookup_kwargs)
        except (User.DoesNotExist, User.MultipleObjectsReturned):
            return self._unauthorized()

        if not self.check_active(user):
            return False

        key_auth_check = self.get_key(user, api_key)
        if key_auth_check and not isinstance(key_auth_check, HttpUnauthorized):
            request.user = user

        return key_auth_check

class GeonodeTokenAuthentication(authentication.TokenAuthentication):
    '''
    Simple token based authentication using utvsapitoken.
    Clients should authenticate by passing the token key in the 'Authorization'
    HTTP header, prepended with the string 'Bearer '.  For example:
    Authorization: Bearer 956e252a-513c-48c5-92dd-bfddc364e812
    '''
    keyword = ['token','bearer']
    def authenticate(self, request):
        auth = authentication.get_authorization_header(request).split()
        if not auth:
            return None
        if auth[0].lower().decode() not in self.keyword:
            return None

        if len(auth) == 1:
            msg = _('Invalid token header. No credentials provided.')
            raise authentication.exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise authentication.exceptions.AuthenticationFailed(msg)
        try:
            token = auth[1].decode()
        except UnicodeError:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise authentication.TokenAuthentication.exceptions.AuthenticationFailed(msg)
        return self.authenticate_credentials(token)
    
    
    def authenticate_credentials(self, key):
        try:
            token = self.model.objects.get(key=key)
        except self.model.DoesNotExist:
            raise authentication.exceptions.AuthenticationFailed('Invalid token')

        if not token.user.is_active:
            raise authentication.exceptions.AuthenticationFailed('User inactive or deleted')

        # This is required for the time comparison
        utc_now = datetime.now(timezone.utc)

        if token.created < utc_now - timedelta(weeks=2):
            raise authentication.exceptions.AuthenticationFailed('Token has expired')

        return token.user, token
    
class GeoNodeStyleAuthorization(GeoNodeAuthorization):
    """Object level API authorization based on GeoNode granular
    permission system

    Style object permissions should follow it's layer permissions
    """

    def filter_by_resource_ids(self, object_list, permitted_ids):
        """Filter Style queryset by permitted resource ids."""
        if check_ogc_backend(geoserver.BACKEND_PACKAGE):
            return object_list.filter(dataset_styles__id__in=permitted_ids)

    def read_list(self, object_list, bundle):
        permitted_ids = get_objects_for_user(bundle.request.user, "base.view_resourcebase").values("id")

        return self.filter_by_resource_ids(object_list, permitted_ids)

    def delete_detail(self, object_list, bundle):
        permitted_ids = get_objects_for_user(bundle.request.user, "layer.change_dataset_style").values("id")

        resource_obj = bundle.obj.get_self_resource()
        return resource_obj in permitted_ids


class ApiLockdownAuthorization(DjangoAuthorization):
    """API authorization for all resources which are not protected  by others authentication/authorization mechanism.
    If setting "API_LOCKDOWN" is set to True, resource can only be accessed by authenticated users. For anonymous
    requests, empty lists are returned.
    """

    def read_list(self, object_list, bundle):
        user = bundle.request.user
        if settings.API_LOCKDOWN and not user.is_authenticated:
            # return empty list
            return []
        else:
            return object_list


class GeoNodePeopleAuthorization(DjangoAuthorization):
    """API authorization that allows only authenticated users to view list of users"""

    def read_list(self, object_list, bundle):
        user = bundle.request.user
        if not user.is_authenticated:
            # return empty list
            return []
        return object_list


class GroupAuthorization(ApiLockdownAuthorization):
    def read_list(self, object_list, bundle):
        groups = super().read_list(object_list, bundle)
        user = bundle.request.user
        if groups:
            if not user.is_authenticated or user.is_anonymous:
                return groups.exclude(groupprofile__access="private")
            elif not user.is_superuser:
                return groups.filter(Q(groupprofile__in=user.group_list_all()) | ~Q(groupprofile__access="private"))
        return groups


class GroupProfileAuthorization(ApiLockdownAuthorization):
    def read_list(self, object_list, bundle):
        groups = super().read_list(object_list, bundle)
        user = bundle.request.user
        if groups:
            if not user.is_authenticated or user.is_anonymous:
                return groups.exclude(access="private")
            elif not user.is_superuser:
                return groups.filter(Q(pk__in=user.group_list_all()) | ~Q(access="private"))
        return groups
