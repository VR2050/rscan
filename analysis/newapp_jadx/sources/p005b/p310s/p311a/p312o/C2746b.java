package p005b.p310s.p311a.p312o;

import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Point;
import android.graphics.Rect;
import android.hardware.Camera;
import android.preference.PreferenceManager;
import java.util.Collections;
import java.util.List;
import p005b.p085c.p088b.p089a.C1345b;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p310s.p311a.p312o.p313f.C2751b;

/* renamed from: b.s.a.o.b */
/* loaded from: classes2.dex */
public final class C2746b {

    /* renamed from: a */
    public final Context f7521a;

    /* renamed from: b */
    public int f7522b;

    /* renamed from: c */
    public int f7523c;

    /* renamed from: d */
    public Point f7524d;

    /* renamed from: e */
    public Point f7525e;

    /* renamed from: f */
    public Point f7526f;

    /* renamed from: g */
    public Point f7527g;

    public C2746b(Context context) {
        this.f7521a = context;
    }

    /* renamed from: a */
    public final void m3259a(Camera.Parameters parameters, boolean z, boolean z2) {
        int i2 = C2747c.f7528a;
        List<String> supportedFlashModes = parameters.getSupportedFlashModes();
        String m3262b = z ? C2747c.m3262b("flash mode", supportedFlashModes, "torch", "on") : C2747c.m3262b("flash mode", supportedFlashModes, "off");
        if (m3262b != null && !m3262b.equals(parameters.getFlashMode())) {
            parameters.setFlashMode(m3262b);
        }
        SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(this.f7521a);
        if (z2 || defaultSharedPreferences.getBoolean("preferences_disable_exposure", true)) {
            return;
        }
        int minExposureCompensation = parameters.getMinExposureCompensation();
        int maxExposureCompensation = parameters.getMaxExposureCompensation();
        float exposureCompensationStep = parameters.getExposureCompensationStep();
        if (minExposureCompensation == 0 && maxExposureCompensation == 0) {
            return;
        }
        if (exposureCompensationStep > 0.0f) {
            int max = Math.max(Math.min(Math.round((z ? 0.0f : 1.5f) / exposureCompensationStep), maxExposureCompensation), minExposureCompensation);
            if (parameters.getExposureCompensation() == max) {
                return;
            }
            parameters.setExposureCompensation(max);
        }
    }

    /* renamed from: b */
    public void m3260b(C2751b c2751b, boolean z) {
        String m3262b;
        String m3262b2;
        Camera camera = c2751b.f7555b;
        Camera.Parameters parameters = camera.getParameters();
        if (parameters == null) {
            return;
        }
        parameters.flatten();
        SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(this.f7521a);
        if (parameters.isZoomSupported()) {
            parameters.setZoom(parameters.getMaxZoom() / 10);
        }
        String string = defaultSharedPreferences.getString("preferences_front_light_mode", "AUTO");
        m3259a(parameters, (string != null ? C1345b.m353e(string) : 2) == 1, z);
        boolean z2 = defaultSharedPreferences.getBoolean("preferences_auto_focus", true);
        boolean z3 = defaultSharedPreferences.getBoolean("preferences_disable_continuous_focus", true);
        int i2 = C2747c.f7528a;
        List<String> supportedFocusModes = parameters.getSupportedFocusModes();
        String m3262b3 = z2 ? (z || z3) ? C2747c.m3262b("focus mode", supportedFocusModes, "auto") : C2747c.m3262b("focus mode", supportedFocusModes, "continuous-picture", "continuous-video", "auto") : null;
        if (!z && m3262b3 == null) {
            m3262b3 = C2747c.m3262b("focus mode", supportedFocusModes, "macro", "edof");
        }
        if (m3262b3 != null && !m3262b3.equals(parameters.getFocusMode())) {
            parameters.setFocusMode(m3262b3);
        }
        if (!z) {
            if (defaultSharedPreferences.getBoolean("preferences_invert_scan", false) && !"negative".equals(parameters.getColorEffect()) && (m3262b2 = C2747c.m3262b("color effect", parameters.getSupportedColorEffects(), "negative")) != null) {
                parameters.setColorEffect(m3262b2);
            }
            if (!defaultSharedPreferences.getBoolean("preferences_disable_barcode_scene_mode", true) && !"barcode".equals(parameters.getSceneMode()) && (m3262b = C2747c.m3262b("scene mode", parameters.getSupportedSceneModes(), "barcode")) != null) {
                parameters.setSceneMode(m3262b);
            }
            if (!defaultSharedPreferences.getBoolean("preferences_disable_metering", true)) {
                if (parameters.isVideoStabilizationSupported() && !parameters.getVideoStabilization()) {
                    parameters.setVideoStabilization(true);
                }
                if (parameters.getMaxNumFocusAreas() > 0) {
                    C2747c.m3263c(parameters.getFocusAreas());
                    List<Camera.Area> singletonList = Collections.singletonList(new Camera.Area(new Rect(-400, -400, 400, 400), 1));
                    C2747c.m3263c(singletonList);
                    parameters.setFocusAreas(singletonList);
                }
                if (parameters.getMaxNumMeteringAreas() > 0) {
                    StringBuilder m586H = C1499a.m586H("Old metering areas: ");
                    m586H.append(parameters.getMeteringAreas());
                    m586H.toString();
                    List<Camera.Area> singletonList2 = Collections.singletonList(new Camera.Area(new Rect(-400, -400, 400, 400), 1));
                    C2747c.m3263c(singletonList2);
                    parameters.setMeteringAreas(singletonList2);
                }
            }
            parameters.setRecordingHint(true);
        }
        Point point = this.f7526f;
        parameters.setPreviewSize(point.x, point.y);
        camera.setParameters(parameters);
        camera.setDisplayOrientation(this.f7523c);
        Camera.Size previewSize = camera.getParameters().getPreviewSize();
        if (previewSize != null) {
            Point point2 = this.f7526f;
            int i3 = point2.x;
            int i4 = previewSize.width;
            if (i3 == i4 && point2.y == previewSize.height) {
                return;
            }
            point2.x = i4;
            point2.y = previewSize.height;
        }
    }
}
