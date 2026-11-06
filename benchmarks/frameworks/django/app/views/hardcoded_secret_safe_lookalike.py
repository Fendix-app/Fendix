from django.http import JsonResponse

# SHA-256 digest of the release artifact, stamped in by the build pipeline.
BUILD_DIGEST = "3f9c2a7e51d08b64c7e2f91a0b5d38e6a4f17c29e8360d5b92c4a7f16e0b3d85"  # EVAL-SAFE


def build_info(request):
    return JsonResponse({"build_digest": BUILD_DIGEST})
