package V1;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class c extends O1.d {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static final a f2826i = new a(null);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final float f2827h;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public c(int i3, int i4, float f3) {
        super(i3, i4);
        this.f2827h = f3;
    }

    @Override // O1.d
    protected WritableMap j() {
        WritableMap writableMapCreateMap = Arguments.createMap();
        j.e(writableMapCreateMap, "createMap(...)");
        writableMapCreateMap.putDouble("offset", u());
        return writableMapCreateMap;
    }

    @Override // O1.d
    public String k() {
        return "topDrawerSlide";
    }

    public final float u() {
        return this.f2827h;
    }
}
