package V1;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class d extends O1.d {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static final a f2828i = new a(null);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final int f2829h;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public d(int i3, int i4, int i5) {
        super(i3, i4);
        this.f2829h = i5;
    }

    @Override // O1.d
    protected WritableMap j() {
        WritableMap writableMapCreateMap = Arguments.createMap();
        j.e(writableMapCreateMap, "createMap(...)");
        writableMapCreateMap.putInt("drawerState", u());
        return writableMapCreateMap;
    }

    @Override // O1.d
    public String k() {
        return "topDrawerStateChanged";
    }

    public final int u() {
        return this.f2829h;
    }
}
