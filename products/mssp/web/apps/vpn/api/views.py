"""
VPN API Views

Provides REST API endpoints for:
- VPN profile management (CRUD)
- Profile download (iOS .mobileconfig, Android, Windows)
- Session monitoring
- Access logs
"""

import logging
from datetime import timedelta

from django.http import HttpResponse, FileResponse
from django.utils import timezone
from django.shortcuts import get_object_or_404

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import JSONParser

from apps.vpn.models import VPNProfile, VPNCertificate, VPNSession, VPNAccessLog
from apps.vpn.services import VPNProfileGenerator, CertificateManager
from .serializers import (
    VPNProfileListSerializer,
    VPNProfileDetailSerializer,
    VPNProfileCreateSerializer,
    VPNCertificateSerializer,
    VPNSessionSerializer,
    VPNAccessLogSerializer,
)

logger = logging.getLogger(__name__)


class VPNProfileViewSet(viewsets.ModelViewSet):
    """
    VPN Profile management endpoints.

    list: Get all VPN profiles for the authenticated user
    create: Create a new VPN profile for a device
    retrieve: Get details of a specific profile
    update: Update profile settings
    destroy: Delete a profile
    download: Download profile for specific platform
    regenerate: Regenerate download token
    """

    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    def get_queryset(self):
        """Filter profiles by authenticated user."""
        return VPNProfile.objects.filter(
            user=self.request.user
        ).select_related('device', 'certificate')

    def get_serializer_class(self):
        if self.action == 'list':
            return VPNProfileListSerializer
        elif self.action == 'create':
            return VPNProfileCreateSerializer
        return VPNProfileDetailSerializer

    def perform_create(self, serializer):
        """Create profile and log access."""
        profile = serializer.save()

        # Log profile creation
        VPNAccessLog.objects.create(
            user=self.request.user,
            action='profile_created',
            profile=profile,
            ip_address=self._get_client_ip(),
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
            details={
                'device_id': str(profile.device.device_id),
                'platform': profile.platform,
            }
        )

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        """
        Download VPN profile for the specified platform.

        Query params:
            platform: ios, android, windows, macos (optional, uses profile default)

        Returns:
            Platform-specific profile file
        """
        profile = self.get_object()

        # Validate profile
        if not profile.is_valid():
            return Response(
                {'error': 'Profile is not valid or has exceeded download limit'},
                status=status.HTTP_403_FORBIDDEN
            )

        if not profile.certificate or not profile.certificate.is_valid():
            return Response(
                {'error': 'Certificate is not valid'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get platform (from query param or profile default)
        platform = request.query_params.get('platform', profile.platform)
        if platform not in ['ios', 'android', 'windows', 'macos', 'universal']:
            return Response(
                {'error': f'Invalid platform: {platform}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            generator = VPNProfileGenerator()
            cert = profile.certificate

            # Common parameters
            params = {
                'profile_name': profile.name,
                'user_identifier': profile.local_identifier,
                'cert_pem': cert.certificate_pem.encode(),
                'encrypted_private_key': bytes(cert.encrypted_private_key),
                'key_iv': bytes(cert.key_encryption_iv),
                'device_name': profile.device.name,
                'route_all_traffic': profile.route_all_traffic,
                'split_tunnel_routes': profile.split_tunnel_routes,
                'dns_servers': profile.dns_servers,
            }

            if platform in ['ios', 'macos']:
                params['on_demand_enabled'] = profile.on_demand_enabled
                profile_data = generator.generate_ios_profile(**params)

                # Update download tracking
                profile.download_count += 1
                profile.last_downloaded = timezone.now()
                profile.save()

                # Log download
                self._log_download(profile, platform)

                response = HttpResponse(
                    profile_data,
                    content_type='application/x-apple-aspen-config'
                )
                response['Content-Disposition'] = (
                    f'attachment; filename="hookprobe_{profile.name}.mobileconfig"'
                )
                return response

            elif platform == 'android':
                result = generator.generate_android_profile(**params)

                profile.download_count += 1
                profile.last_downloaded = timezone.now()
                profile.save()

                self._log_download(profile, platform)

                return Response(result)

            elif platform == 'windows':
                result = generator.generate_windows_profile(**params)

                profile.download_count += 1
                profile.last_downloaded = timezone.now()
                profile.save()

                self._log_download(profile, platform)

                return Response(result)

            else:  # universal
                result = generator.generate_universal_bundle(**params)

                profile.download_count += 1
                profile.last_downloaded = timezone.now()
                profile.save()

                self._log_download(profile, 'universal')

                return Response(result)

        except Exception as e:
            logger.exception(f"Error generating profile: {e}")
            return Response(
                {'error': 'Failed to generate profile'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['post'])
    def regenerate(self, request, pk=None):
        """
        Regenerate download token and reset download counter.

        Use this when the profile has exceeded its download limit
        or if the token may have been compromised.
        """
        profile = self.get_object()
        profile.regenerate_token()

        return Response({
            'message': 'Profile token regenerated',
            'download_count': profile.download_count,
            'max_downloads': profile.max_downloads,
        })

    @action(detail=True, methods=['post'])
    def revoke(self, request, pk=None):
        """
        Revoke a VPN profile and its certificate.

        This will immediately invalidate the profile and prevent
        any further VPN connections.
        """
        profile = self.get_object()

        # Revoke certificate
        if profile.certificate:
            profile.certificate.revoke(reason="User requested revocation")

        # Deactivate profile
        profile.is_active = False
        profile.save()

        # Log revocation
        VPNAccessLog.objects.create(
            user=self.request.user,
            action='profile_revoked',
            profile=profile,
            ip_address=self._get_client_ip(),
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
        )

        return Response({'message': 'Profile and certificate revoked'})

    @action(detail=True, methods=['get'])
    def sessions(self, request, pk=None):
        """Get all sessions for this profile."""
        profile = self.get_object()
        sessions = VPNSession.objects.filter(profile=profile).order_by('-started_at')[:50]
        serializer = VPNSessionSerializer(sessions, many=True)
        return Response(serializer.data)

    def _log_download(self, profile, platform):
        """Log profile download."""
        VPNAccessLog.objects.create(
            user=self.request.user,
            action='profile_downloaded',
            profile=profile,
            ip_address=self._get_client_ip(),
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
            details={
                'platform': platform,
                'download_count': profile.download_count,
            }
        )

    def _get_client_ip(self):
        """Get client IP from request."""
        x_forwarded = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded:
            return x_forwarded.split(',')[0].strip()
        return self.request.META.get('REMOTE_ADDR')


class VPNCertificateViewSet(viewsets.ReadOnlyModelViewSet):
    """
    VPN Certificate endpoints (read-only).

    Certificates are created automatically with profiles.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = VPNCertificateSerializer

    def get_queryset(self):
        return VPNCertificate.objects.filter(user=self.request.user)

    @action(detail=True, methods=['post'])
    def revoke(self, request, pk=None):
        """Revoke a certificate."""
        cert = self.get_object()
        reason = request.data.get('reason', 'User requested revocation')
        cert.revoke(reason=reason)

        VPNAccessLog.objects.create(
            user=self.request.user,
            action='cert_revoked',
            ip_address=self._get_client_ip(),
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
            details={'serial_number': cert.serial_number, 'reason': reason}
        )

        return Response({'message': 'Certificate revoked'})

    def _get_client_ip(self):
        x_forwarded = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded:
            return x_forwarded.split(',')[0].strip()
        return self.request.META.get('REMOTE_ADDR')


class VPNSessionViewSet(viewsets.ReadOnlyModelViewSet):
    """
    VPN Session endpoints (read-only).

    Sessions are created/updated by the VPN server.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = VPNSessionSerializer

    def get_queryset(self):
        return VPNSession.objects.filter(
            profile__user=self.request.user
        ).select_related('profile', 'profile__device')

    @action(detail=False, methods=['get'])
    def active(self, request):
        """Get currently active sessions."""
        sessions = self.get_queryset().filter(is_active=True)
        serializer = self.get_serializer(sessions, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get session statistics."""
        from django.db.models import Sum, Count, Avg

        queryset = self.get_queryset()

        # Calculate stats
        stats = queryset.aggregate(
            total_sessions=Count('id'),
            active_sessions=Count('id', filter=models.Q(is_active=True)),
            total_bytes_in=Sum('bytes_in'),
            total_bytes_out=Sum('bytes_out'),
            avg_latency=Avg('avg_latency_ms'),
        )

        # Add human-readable bandwidth
        total_bytes = (stats['total_bytes_in'] or 0) + (stats['total_bytes_out'] or 0)
        stats['total_bandwidth_gb'] = round(total_bytes / (1024**3), 2)

        return Response(stats)


class VPNAccessLogViewSet(viewsets.ReadOnlyModelViewSet):
    """VPN Access log endpoints (read-only)."""

    permission_classes = [IsAuthenticated]
    serializer_class = VPNAccessLogSerializer

    def get_queryset(self):
        return VPNAccessLog.objects.filter(user=self.request.user)


# For stats query
from django.db import models
