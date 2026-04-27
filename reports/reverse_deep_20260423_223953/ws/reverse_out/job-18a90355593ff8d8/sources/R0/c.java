package R0;

import N0.j;
import Q0.i;
import Q0.r;
import X.k;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.ColorSpace;
import android.graphics.Rect;
import android.os.Build;
import b0.AbstractC0311a;
import com.facebook.imagepipeline.platform.PreverificationHelper;
import d0.C0503a;
import d0.C0504b;
import java.io.IOException;
import java.io.InputStream;

/* JADX INFO: loaded from: classes.dex */
public abstract class c implements f {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final Class f2621f = c.class;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final byte[] f2622g = {-1, -39};

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final i f2623a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f2624b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f2625c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final PreverificationHelper f2626d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    final q.e f2627e;

    public c(i iVar, q.e eVar, h hVar) {
        this.f2626d = Build.VERSION.SDK_INT >= 26 ? new PreverificationHelper() : null;
        this.f2623a = iVar;
        if (iVar instanceof r) {
            this.f2624b = hVar.a();
            this.f2625c = hVar.b();
        }
        this.f2627e = eVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:30:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0075  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00c4  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00c7 A[Catch: all -> 0x00a3, RuntimeException -> 0x00a6, IllegalArgumentException -> 0x00a8, TRY_LEAVE, TryCatch #8 {IllegalArgumentException -> 0x00a8, RuntimeException -> 0x00a6, blocks: (B:36:0x007d, B:39:0x0087, B:49:0x009f, B:68:0x00c7, B:64:0x00c0, B:65:0x00c3, B:62:0x00ba), top: B:98:0x007d, outer: #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:79:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x00f1  */
    /* JADX WARN: Type inference failed for: r0v1, types: [int] */
    /* JADX WARN: Type inference failed for: r0v7 */
    /* JADX WARN: Type inference failed for: r0v8 */
    /* JADX WARN: Type inference fix 'apply assigned field type' failed
    java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$UnknownArg
    	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
    	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
    	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private b0.AbstractC0311a c(java.io.InputStream r9, android.graphics.BitmapFactory.Options r10, android.graphics.Rect r11, android.graphics.ColorSpace r12) {
        /*
            Method dump skipped, instruction units count: 294
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: R0.c.c(java.io.InputStream, android.graphics.BitmapFactory$Options, android.graphics.Rect, android.graphics.ColorSpace):b0.a");
    }

    private static BitmapFactory.Options e(j jVar, Bitmap.Config config, boolean z3) {
        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inSampleSize = jVar.Z();
        options.inJustDecodeBounds = true;
        options.inDither = true;
        boolean z4 = Build.VERSION.SDK_INT >= 26 && config == Bitmap.Config.HARDWARE;
        if (!z4) {
            options.inPreferredConfig = config;
        }
        options.inMutable = true;
        if (!z3) {
            BitmapFactory.decodeStream(jVar.P(), null, options);
            if (options.outWidth == -1 || options.outHeight == -1) {
                throw new IllegalArgumentException();
            }
        }
        if (z4) {
            options.inPreferredConfig = config;
        }
        options.inJustDecodeBounds = false;
        return options;
    }

    @Override // R0.f
    public AbstractC0311a a(j jVar, Bitmap.Config config, Rect rect, int i3, ColorSpace colorSpace) {
        boolean zT0 = jVar.t0(i3);
        BitmapFactory.Options optionsE = e(jVar, config, this.f2624b);
        InputStream inputStreamP = jVar.P();
        k.g(inputStreamP);
        if (jVar.d0() > i3) {
            inputStreamP = new C0503a(inputStreamP, i3);
        }
        if (!zT0) {
            inputStreamP = new C0504b(inputStreamP, f2622g);
        }
        boolean z3 = optionsE.inPreferredConfig != Bitmap.Config.ARGB_8888;
        try {
            try {
                return c(inputStreamP, optionsE, rect, colorSpace);
            } catch (RuntimeException e3) {
                if (!z3) {
                    throw e3;
                }
                AbstractC0311a abstractC0311aA = a(jVar, Bitmap.Config.ARGB_8888, rect, i3, colorSpace);
                try {
                    inputStreamP.close();
                } catch (IOException e4) {
                    e4.printStackTrace();
                }
                return abstractC0311aA;
            }
        } finally {
            try {
                inputStreamP.close();
            } catch (IOException e5) {
                e5.printStackTrace();
            }
        }
    }

    @Override // R0.f
    public AbstractC0311a b(j jVar, Bitmap.Config config, Rect rect, ColorSpace colorSpace) {
        BitmapFactory.Options optionsE = e(jVar, config, this.f2624b);
        boolean z3 = optionsE.inPreferredConfig != Bitmap.Config.ARGB_8888;
        try {
            return c((InputStream) k.g(jVar.P()), optionsE, rect, colorSpace);
        } catch (RuntimeException e3) {
            if (z3) {
                return b(jVar, Bitmap.Config.ARGB_8888, rect, colorSpace);
            }
            throw e3;
        }
    }

    public abstract int d(int i3, int i4, BitmapFactory.Options options);

    private static final class a implements b0.g {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private static final a f2628a = new a();

        private a() {
        }

        @Override // b0.g
        /* JADX INFO: renamed from: c, reason: merged with bridge method [inline-methods] */
        public void a(Bitmap bitmap) {
        }
    }
}
