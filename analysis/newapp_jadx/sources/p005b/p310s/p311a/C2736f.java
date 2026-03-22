package p005b.p310s.p311a;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import p005b.p310s.p311a.p312o.C2748d;

/* renamed from: b.s.a.f */
/* loaded from: classes2.dex */
public final class C2736f implements SensorEventListener {

    /* renamed from: a */
    public float f7440a = 45.0f;

    /* renamed from: b */
    public float f7441b = 100.0f;

    /* renamed from: c */
    public final Context f7442c;

    /* renamed from: d */
    public C2748d f7443d;

    /* renamed from: e */
    public Sensor f7444e;

    public C2736f(Context context) {
        this.f7442c = context;
    }

    @Override // android.hardware.SensorEventListener
    public void onAccuracyChanged(Sensor sensor, int i2) {
    }

    @Override // android.hardware.SensorEventListener
    public void onSensorChanged(SensorEvent sensorEvent) {
        float f2 = sensorEvent.values[0];
        C2748d c2748d = this.f7443d;
        if (c2748d != null) {
            if (f2 <= this.f7440a) {
                c2748d.m3269f(true, f2);
            } else if (f2 >= this.f7441b) {
                c2748d.m3269f(false, f2);
            }
        }
    }
}
