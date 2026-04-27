package d1;

import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;

/* JADX INFO: loaded from: classes.dex */
public final class g implements SensorEventListener {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final a f9164a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f9165b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private float f9166c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private float f9167d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private float f9168e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private SensorManager f9169f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private long f9170g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int f9171h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private long f9172i;

    public interface a {
        void a();
    }

    public g(a aVar, int i3) {
        t2.j.f(aVar, "shakeListener");
        this.f9164a = aVar;
        this.f9165b = i3;
    }

    private final boolean a(float f3) {
        return Math.abs(f3) > 13.042845f;
    }

    private final void b(long j3) {
        if (this.f9171h >= this.f9165b * 8) {
            d();
            this.f9164a.a();
        }
        if (j3 - this.f9172i > h.f9174b) {
            d();
        }
    }

    private final void c(long j3) {
        this.f9172i = j3;
        this.f9171h++;
    }

    private final void d() {
        this.f9171h = 0;
        this.f9166c = 0.0f;
        this.f9167d = 0.0f;
        this.f9168e = 0.0f;
    }

    public final void e(SensorManager sensorManager) {
        t2.j.f(sensorManager, "manager");
        Sensor defaultSensor = sensorManager.getDefaultSensor(1);
        if (defaultSensor == null) {
            return;
        }
        this.f9169f = sensorManager;
        this.f9170g = -1L;
        sensorManager.registerListener(this, defaultSensor, 2);
        this.f9172i = 0L;
        d();
    }

    public final void f() {
        SensorManager sensorManager = this.f9169f;
        if (sensorManager != null) {
            sensorManager.unregisterListener(this);
        }
        this.f9169f = null;
    }

    @Override // android.hardware.SensorEventListener
    public void onAccuracyChanged(Sensor sensor, int i3) {
        t2.j.f(sensor, "sensor");
    }

    @Override // android.hardware.SensorEventListener
    public void onSensorChanged(SensorEvent sensorEvent) {
        t2.j.f(sensorEvent, "sensorEvent");
        if (sensorEvent.timestamp - this.f9170g < h.f9173a) {
            return;
        }
        float[] fArr = sensorEvent.values;
        float f3 = fArr[0];
        float f4 = fArr[1];
        float f5 = fArr[2] - 9.80665f;
        this.f9170g = sensorEvent.timestamp;
        if (a(f3) && this.f9166c * f3 <= 0.0f) {
            c(sensorEvent.timestamp);
            this.f9166c = f3;
        } else if (a(f4) && this.f9167d * f4 <= 0.0f) {
            c(sensorEvent.timestamp);
            this.f9167d = f4;
        } else if (a(f5) && this.f9168e * f5 <= 0.0f) {
            c(sensorEvent.timestamp);
            this.f9168e = f5;
        }
        b(sensorEvent.timestamp);
    }
}
