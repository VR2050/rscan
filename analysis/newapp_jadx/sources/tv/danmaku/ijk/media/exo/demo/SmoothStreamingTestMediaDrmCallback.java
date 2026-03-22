package tv.danmaku.ijk.media.exo.demo;

import android.annotation.TargetApi;
import android.text.TextUtils;
import com.google.android.exoplayer.drm.ExoMediaDrm;
import com.google.android.exoplayer.drm.MediaDrmCallback;
import com.google.android.exoplayer.util.Util;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import p005b.p131d.p132a.p133a.C1499a;

@TargetApi(18)
/* loaded from: classes3.dex */
public class SmoothStreamingTestMediaDrmCallback implements MediaDrmCallback {
    private static final String PLAYREADY_TEST_DEFAULT_URI = "http://playready.directtaps.net/pr/svc/rightsmanager.asmx";
    private static final Map<String, String> PROVISIONING_REQUEST_PROPERTIES = Collections.singletonMap("Content-Type", "application/octet-stream");
    private static final Map<String, String> KEY_REQUEST_PROPERTIES = C1499a.m596R("Content-Type", "text/xml", "SOAPAction", "http://schemas.microsoft.com/DRM/2007/03/protocols/AcquireLicense");

    public byte[] executeKeyRequest(UUID uuid, ExoMediaDrm.KeyRequest keyRequest) {
        String defaultUrl = keyRequest.getDefaultUrl();
        if (TextUtils.isEmpty(defaultUrl)) {
            defaultUrl = PLAYREADY_TEST_DEFAULT_URI;
        }
        return Util.executePost(defaultUrl, keyRequest.getData(), KEY_REQUEST_PROPERTIES);
    }

    public byte[] executeProvisionRequest(UUID uuid, ExoMediaDrm.ProvisionRequest provisionRequest) {
        return Util.executePost(provisionRequest.getDefaultUrl() + "&signedRequest=" + new String(provisionRequest.getData()), (byte[]) null, PROVISIONING_REQUEST_PROPERTIES);
    }
}
