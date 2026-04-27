package O1;

import O1.d;
import android.view.MotionEvent;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.uimanager.C0;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.events.RCTEventEmitter;
import com.facebook.react.uimanager.events.RCTModernEventEmitter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
public class n extends d {

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private static final String f2086n = "n";

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private static final q.f f2087o = new q.f(6);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private MotionEvent f2088h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private String f2089i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private short f2090j = -1;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private List f2091k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private b f2092l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private d.b f2093m;

    class a implements d.b {
        a() {
        }

        @Override // O1.d.b
        public boolean a(int i3, String str) {
            if (!str.equals(n.this.f2089i)) {
                return false;
            }
            if (!o.f(str)) {
                return n.this.o() == i3;
            }
            Iterator it = n.this.f2092l.e().iterator();
            while (it.hasNext()) {
                if (((C0.b) it.next()).b() == i3) {
                    return true;
                }
            }
            return false;
        }
    }

    public static class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private int f2095a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private int f2096b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private int f2097c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private int f2098d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private Map f2099e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private Map f2100f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private Map f2101g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private Map f2102h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private Set f2103i;

        public b(int i3, int i4, int i5, int i6, Map map, Map map2, Map map3, Map map4, Set set) {
            this.f2095a = i3;
            this.f2096b = i4;
            this.f2097c = i5;
            this.f2098d = i6;
            this.f2099e = map;
            this.f2100f = map2;
            this.f2101g = map3;
            this.f2102h = map4;
            this.f2103i = new HashSet(set);
        }

        public int b() {
            return this.f2096b;
        }

        public final Map c() {
            return this.f2101g;
        }

        public final Map d() {
            return this.f2100f;
        }

        public final List e() {
            return (List) this.f2100f.get(Integer.valueOf(this.f2096b));
        }

        public Set f() {
            return this.f2103i;
        }

        public int g() {
            return this.f2097c;
        }

        public final Map h() {
            return this.f2099e;
        }

        public int i() {
            return this.f2095a;
        }

        public final Map j() {
            return this.f2102h;
        }

        public int k() {
            return this.f2098d;
        }

        public boolean l(int i3) {
            return this.f2103i.contains(Integer.valueOf(i3));
        }
    }

    private n() {
    }

    private void A(String str, int i3, b bVar, MotionEvent motionEvent, short s3) {
        super.r(bVar.k(), i3, motionEvent.getEventTime());
        this.f2089i = str;
        this.f2088h = MotionEvent.obtain(motionEvent);
        this.f2090j = s3;
        this.f2092l = bVar;
    }

    private boolean B() {
        return this.f2089i.equals("topClick");
    }

    public static n C(String str, int i3, b bVar, MotionEvent motionEvent) {
        n nVar = (n) f2087o.b();
        if (nVar == null) {
            nVar = new n();
        }
        nVar.A(str, i3, bVar, (MotionEvent) Z0.a.c(motionEvent), (short) 0);
        return nVar;
    }

    public static n D(String str, int i3, b bVar, MotionEvent motionEvent, short s3) {
        n nVar = (n) f2087o.b();
        if (nVar == null) {
            nVar = new n();
        }
        nVar.A(str, i3, bVar, (MotionEvent) Z0.a.c(motionEvent), s3);
        return nVar;
    }

    private void w(WritableMap writableMap, int i3) {
        writableMap.putBoolean("ctrlKey", (i3 & 4096) != 0);
        writableMap.putBoolean("shiftKey", (i3 & 1) != 0);
        writableMap.putBoolean("altKey", (i3 & 2) != 0);
        writableMap.putBoolean("metaKey", (i3 & 65536) != 0);
    }

    private List x() {
        int actionIndex;
        actionIndex = this.f2088h.getActionIndex();
        String str = this.f2089i;
        str.hashCode();
        switch (str) {
            case "topPointerEnter":
            case "topPointerLeave":
            case "topPointerDown":
            case "topPointerOver":
            case "topPointerUp":
            case "topClick":
            case "topPointerOut":
                return Arrays.asList(y(actionIndex));
            case "topPointerMove":
            case "topPointerCancel":
                return z();
            default:
                return null;
        }
    }

    private WritableMap y(int i3) {
        WritableMap writableMapCreateMap = Arguments.createMap();
        int pointerId = this.f2088h.getPointerId(i3);
        writableMapCreateMap.putDouble("pointerId", pointerId);
        String strE = o.e(this.f2088h.getToolType(i3));
        writableMapCreateMap.putString("pointerType", strE);
        writableMapCreateMap.putBoolean("isPrimary", !B() && (this.f2092l.l(pointerId) || pointerId == this.f2092l.f2095a));
        float[] fArr = (float[]) this.f2092l.c().get(Integer.valueOf(pointerId));
        double dF = C0444f0.f(fArr[0]);
        double dF2 = C0444f0.f(fArr[1]);
        writableMapCreateMap.putDouble("clientX", dF);
        writableMapCreateMap.putDouble("clientY", dF2);
        float[] fArr2 = (float[]) this.f2092l.j().get(Integer.valueOf(pointerId));
        double dF3 = C0444f0.f(fArr2[0]);
        double dF4 = C0444f0.f(fArr2[1]);
        writableMapCreateMap.putDouble("screenX", dF3);
        writableMapCreateMap.putDouble("screenY", dF4);
        writableMapCreateMap.putDouble("x", dF);
        writableMapCreateMap.putDouble("y", dF2);
        writableMapCreateMap.putDouble("pageX", dF);
        writableMapCreateMap.putDouble("pageY", dF2);
        float[] fArr3 = (float[]) this.f2092l.h().get(Integer.valueOf(pointerId));
        writableMapCreateMap.putDouble("offsetX", C0444f0.f(fArr3[0]));
        writableMapCreateMap.putDouble("offsetY", C0444f0.f(fArr3[1]));
        writableMapCreateMap.putInt("target", o());
        writableMapCreateMap.putDouble("timestamp", m());
        writableMapCreateMap.putInt("detail", 0);
        writableMapCreateMap.putDouble("tiltX", 0.0d);
        writableMapCreateMap.putDouble("tiltY", 0.0d);
        writableMapCreateMap.putInt("twist", 0);
        if (strE.equals("mouse") || B()) {
            writableMapCreateMap.putDouble("width", 1.0d);
            writableMapCreateMap.putDouble("height", 1.0d);
        } else {
            double dF5 = C0444f0.f(this.f2088h.getTouchMajor(i3));
            writableMapCreateMap.putDouble("width", dF5);
            writableMapCreateMap.putDouble("height", dF5);
        }
        int buttonState = this.f2088h.getButtonState();
        writableMapCreateMap.putInt("button", o.a(strE, this.f2092l.g(), buttonState));
        writableMapCreateMap.putInt("buttons", o.b(this.f2089i, strE, buttonState));
        writableMapCreateMap.putDouble("pressure", B() ? 0.0d : o.d(writableMapCreateMap.getInt("buttons"), this.f2089i));
        writableMapCreateMap.putDouble("tangentialPressure", 0.0d);
        w(writableMapCreateMap, this.f2088h.getMetaState());
        return writableMapCreateMap;
    }

    private List z() {
        ArrayList arrayList = new ArrayList();
        for (int i3 = 0; i3 < this.f2088h.getPointerCount(); i3++) {
            arrayList.add(y(i3));
        }
        return arrayList;
    }

    @Override // O1.d
    public void c(RCTEventEmitter rCTEventEmitter) {
        if (this.f2088h == null) {
            ReactSoftExceptionLogger.logSoftException(f2086n, new IllegalStateException("Cannot dispatch a Pointer that has no MotionEvent; the PointerEvehas been recycled"));
            return;
        }
        if (this.f2091k == null) {
            this.f2091k = x();
        }
        List list = this.f2091k;
        if (list == null) {
            return;
        }
        boolean z3 = list.size() > 1;
        for (WritableMap writableMapCopy : this.f2091k) {
            if (z3) {
                writableMapCopy = writableMapCopy.copy();
            }
            rCTEventEmitter.receiveEvent(o(), this.f2089i, writableMapCopy);
        }
    }

    @Override // O1.d
    public void d(RCTModernEventEmitter rCTModernEventEmitter) {
        if (this.f2088h == null) {
            ReactSoftExceptionLogger.logSoftException(f2086n, new IllegalStateException("Cannot dispatch a Pointer that has no MotionEvent; the PointerEvehas been recycled"));
            return;
        }
        if (this.f2091k == null) {
            this.f2091k = x();
        }
        List list = this.f2091k;
        if (list == null) {
            return;
        }
        boolean z3 = list.size() > 1;
        for (WritableMap writableMapCopy : this.f2091k) {
            if (z3) {
                writableMapCopy = writableMapCopy.copy();
            }
            WritableMap writableMap = writableMapCopy;
            int iL = l();
            int iO = o();
            String str = this.f2089i;
            short s3 = this.f2090j;
            rCTModernEventEmitter.receiveEvent(iL, iO, str, s3 != -1, s3, writableMap, o.c(str));
        }
    }

    @Override // O1.d
    public short g() {
        return this.f2090j;
    }

    @Override // O1.d
    public d.b h() {
        if (this.f2093m == null) {
            this.f2093m = new a();
        }
        return this.f2093m;
    }

    @Override // O1.d
    public String k() {
        return this.f2089i;
    }

    @Override // O1.d
    public void t() {
        this.f2091k = null;
        MotionEvent motionEvent = this.f2088h;
        this.f2088h = null;
        if (motionEvent != null) {
            motionEvent.recycle();
        }
        try {
            f2087o.a(this);
        } catch (IllegalStateException e3) {
            ReactSoftExceptionLogger.logSoftException(f2086n, e3);
        }
    }
}
