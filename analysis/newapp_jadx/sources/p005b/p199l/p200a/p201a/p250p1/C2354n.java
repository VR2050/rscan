package p005b.p199l.p200a.p201a.p250p1;

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.animation.ValueAnimator;
import android.app.Activity;
import android.app.Application;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.content.res.XmlResourceParser;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.opengl.GLES20;
import android.opengl.GLU;
import android.os.Build;
import android.os.Environment;
import android.os.Trace;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.method.LinkMovementMethod;
import android.text.style.ForegroundColorSpan;
import android.text.style.ReplacementSpan;
import android.text.style.UnderlineSpan;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.util.Log;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.DrawableRes;
import androidx.annotation.NonNull;
import androidx.appcompat.widget.ActivityChooserModel;
import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;
import androidx.core.content.res.ResourcesCompat;
import androidx.core.view.ViewCompat;
import androidx.exifinterface.media.ExifInterface;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.lifecycle.LifecycleCoroutineScope;
import androidx.lifecycle.ViewModelKt;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.viewbinding.ViewBinding;
import com.drake.brv.BindingAdapter;
import com.drake.brv.PageRefreshLayout;
import com.google.android.material.imageview.ShapeableImageView;
import com.google.android.material.shape.ShapeAppearanceModel;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.TokenBean;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import com.view.text.view.TagItemView;
import com.yalantis.ucrop.view.CropImageView;
import es.dmoral.toasty.R$color;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.io.StringWriter;
import java.lang.ref.WeakReference;
import java.lang.reflect.Array;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.net.IDN;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import kotlin.ExceptionsKt__ExceptionsKt;
import kotlin.PublishedApi;
import kotlin.Result;
import kotlin.ResultKt;
import kotlin.TypeCastException;
import kotlin.UShort;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.ContinuationInterceptor;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.DebugProbesKt;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.jvm.internal.StringCompanionObject;
import kotlin.jvm.internal.TypeIntrinsics;
import kotlin.ranges.RangesKt___RangesKt;
import kotlin.text.Charsets;
import kotlin.text.StringsKt__StringNumberConversionsKt;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import kotlin.time.DurationKt;
import kotlinx.coroutines.CoroutineExceptionHandler;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.xmlpull.v1.XmlPullParser;
import p005b.p006a.p007a.p008a.C0887j;
import p005b.p006a.p007a.p008a.p009a.C0839c0;
import p005b.p006a.p007a.p008a.p009a.C0845f0;
import p005b.p081b0.p082a.p083a.C1325b;
import p005b.p081b0.p082a.p084b.C1327a;
import p005b.p081b0.p082a.p084b.C1329c;
import p005b.p085c.p088b.p089a.C1345b;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p139f.p140a.p142b.C1535e;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.p264d0.C2470a;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.EnumC2524f;
import p005b.p199l.p266d.p267a0.C2499b;
import p005b.p199l.p266d.p267a0.p270e.C2517b;
import p005b.p199l.p266d.p274v.C2544b;
import p005b.p293n.p294a.C2648g;
import p005b.p295o.p296a.p297a.C2673a;
import p005b.p295o.p296a.p297a.C2675c;
import p005b.p295o.p296a.p297a.C2680h;
import p005b.p327w.p330b.p331b.p333d.C2832a;
import p005b.p327w.p330b.p331b.p333d.C2834c;
import p005b.p327w.p330b.p331b.p333d.C2835d;
import p005b.p327w.p330b.p331b.p333d.C2837f;
import p005b.p327w.p330b.p331b.p334e.InterfaceC2846i;
import p005b.p327w.p330b.p336c.C2852c;
import p005b.p362y.p363a.p365e.InterfaceC2922a;
import p005b.p362y.p363a.p368h.InterfaceC2937c;
import p005b.p375z.p376a.p377a.C2949a;
import p005b.p375z.p376a.p377a.C2950b;
import p005b.p375z.p376a.p377a.p378c.C2951a;
import p379c.p380a.AbstractC3076l0;
import p379c.p380a.C2976a0;
import p379c.p380a.C3052d0;
import p379c.p380a.C3062g1;
import p379c.p380a.C3064h0;
import p379c.p380a.C3069j;
import p379c.p380a.C3071j1;
import p379c.p380a.C3073k0;
import p379c.p380a.C3074k1;
import p379c.p380a.C3079m0;
import p379c.p380a.C3098s1;
import p379c.p380a.C3108w;
import p379c.p380a.C3111x;
import p379c.p380a.C3113x1;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.InterfaceC3070j0;
import p379c.p380a.InterfaceC3082n0;
import p379c.p380a.InterfaceC3102u;
import p379c.p380a.p381a.C2952a;
import p379c.p380a.p381a.C2956e;
import p379c.p380a.p381a.C2957f;
import p379c.p380a.p381a.C2958g;
import p379c.p380a.p381a.C2964m;
import p379c.p380a.p381a.C2968q;
import p379c.p380a.p381a.C2971t;
import p379c.p380a.p381a.C2975x;
import p379c.p380a.p382a2.C2981d;
import p379c.p380a.p382a2.C2988k;
import p379c.p380a.p382a2.C2989l;
import p379c.p380a.p382a2.C2996s;
import p379c.p380a.p382a2.EnumC2982e;
import p379c.p380a.p382a2.InterfaceC2983f;
import p379c.p380a.p382a2.InterfaceC2994q;
import p379c.p380a.p383b2.C3013i;
import p379c.p380a.p383b2.C3014j;
import p379c.p380a.p383b2.C3015k;
import p379c.p380a.p383b2.InterfaceC3006b;
import p379c.p380a.p383b2.p384n.C3023f;
import p379c.p380a.p383b2.p384n.C3033p;
import p379c.p380a.p383b2.p384n.InterfaceC3026i;
import p403d.p404a.p405a.p407b.p408a.C4195m;
import p426f.p427a.p428a.C4325a;
import p429g.p433b.p434a.p437c.C4337a;
import p429g.p433b.p434a.p437c.C4338b;
import p429g.p433b.p434a.p437c.C4340d;
import p429g.p433b.p434a.p439e.p443d.C4345a;
import p458k.AbstractC4387j0;
import p458k.C4371b0;
import p458k.C4385i0;
import p458k.p459p0.C4401c;
import p458k.p459p0.p461e.AbstractC4408a;
import p458k.p459p0.p461e.C4409b;
import p458k.p459p0.p461e.C4410c;
import p474l.C4737a0;
import p474l.C4741c;
import p474l.C4742d;
import p474l.C4744f;
import p474l.C4753o;
import p474l.C4754p;
import p474l.C4756r;
import p474l.C4757s;
import p474l.C4758t;
import p474l.C4761w;
import p474l.C4763y;
import p474l.InterfaceC4745g;
import p474l.InterfaceC4746h;
import p474l.InterfaceC4762x;
import p474l.InterfaceC4764z;
import p474l.p475b0.C4740b;
import p476m.p477a.p478a.p483b.C4786c;

/* renamed from: b.l.a.a.p1.n */
/* loaded from: classes.dex */
public final class C2354n {

    /* renamed from: a */
    public static float f6087a;

    /* renamed from: b */
    public static Class<? extends InterfaceC2922a> f6088b;

    /* renamed from: c */
    public static Class<? extends InterfaceC2937c> f6089c;

    /* renamed from: d */
    public static String f6090d;

    /* renamed from: b.l.a.a.p1.n$a */
    /* loaded from: classes2.dex */
    public static final class a extends C2470a<HashMap<String, Object>> {
    }

    /* renamed from: b.l.a.a.p1.n$b */
    /* loaded from: classes2.dex */
    public static class b implements ValueAnimator.AnimatorUpdateListener {

        /* renamed from: c */
        public final /* synthetic */ View f6091c;

        public b(View view) {
            this.f6091c = view;
        }

        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
        public void onAnimationUpdate(ValueAnimator valueAnimator) {
            this.f6091c.getLayoutParams().height = ((Integer) valueAnimator.getAnimatedValue()).intValue();
            this.f6091c.requestLayout();
        }
    }

    /* renamed from: b.l.a.a.p1.n$c */
    /* loaded from: classes2.dex */
    public static final class c extends Lambda implements Function1<String, Unit> {

        /* renamed from: c */
        public final /* synthetic */ Function1<String, Unit> f6092c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public c(Function1<? super String, Unit> function1) {
            super(1);
            this.f6092c = function1;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(String str) {
            String str2 = str;
            Function1<String, Unit> function1 = this.f6092c;
            if (str2 == null) {
                str2 = "";
            }
            function1.invoke(str2);
            return Unit.INSTANCE;
        }
    }

    /* renamed from: b.l.a.a.p1.n$d */
    /* loaded from: classes2.dex */
    public static final class d extends Lambda implements Function1<View, Unit> {

        /* renamed from: c */
        public final /* synthetic */ Function1<View, Unit> f6093c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public d(Function1<? super View, Unit> function1) {
            super(1);
            this.f6093c = function1;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(View view) {
            this.f6093c.invoke(view);
            return Unit.INSTANCE;
        }
    }

    @DebugMetadata(m5319c = "kotlinx.coroutines.flow.FlowKt__ChannelsKt", m5320f = "Channels.kt", m5321i = {0, 0, 0, 0, 0, 1, 1, 1, 1, 1}, m5322l = {50, 61}, m5323m = "emitAllImpl$FlowKt__ChannelsKt", m5324n = {"$this$emitAllImpl", "channel", "consume", "cause", "$this$run", "$this$emitAllImpl", "channel", "consume", "cause", "result"}, m5325s = {"L$0", "L$1", "Z$0", "L$2", "L$3", "L$0", "L$1", "Z$0", "L$2", "L$3"})
    /* renamed from: b.l.a.a.p1.n$e */
    /* loaded from: classes2.dex */
    public static final class e extends ContinuationImpl {

        /* renamed from: c */
        public /* synthetic */ Object f6094c;

        /* renamed from: e */
        public int f6095e;

        /* renamed from: f */
        public Object f6096f;

        /* renamed from: g */
        public Object f6097g;

        /* renamed from: h */
        public Object f6098h;

        /* renamed from: i */
        public Object f6099i;

        /* renamed from: j */
        public boolean f6100j;

        public e(Continuation continuation) {
            super(continuation);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            this.f6094c = obj;
            this.f6095e |= Integer.MIN_VALUE;
            return C2354n.m2440W(null, null, false, this);
        }
    }

    @DebugMetadata(m5319c = "kotlinx.coroutines.flow.FlowKt__EmittersKt", m5320f = "Emitters.kt", m5321i = {0, 0, 0}, m5322l = {208}, m5323m = "invokeSafely$FlowKt__EmittersKt", m5324n = {"$this$invokeSafely", "action", "cause"}, m5325s = {"L$0", "L$1", "L$2"})
    /* renamed from: b.l.a.a.p1.n$f */
    /* loaded from: classes2.dex */
    public static final class f extends ContinuationImpl {

        /* renamed from: c */
        public /* synthetic */ Object f6101c;

        /* renamed from: e */
        public int f6102e;

        /* renamed from: f */
        public Object f6103f;

        /* renamed from: g */
        public Object f6104g;

        /* renamed from: h */
        public Object f6105h;

        public f(Continuation continuation) {
            super(continuation);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            this.f6101c = obj;
            this.f6102e |= Integer.MIN_VALUE;
            return C2354n.m2534z0(null, null, null, this);
        }
    }

    /* renamed from: A */
    public static /* synthetic */ void m2374A(View view, long j2, Function1 function1, int i2) {
        if ((i2 & 1) != 0) {
            j2 = 1000;
        }
        m2533z(view, j2, function1);
    }

    /* renamed from: A0 */
    public static boolean m2375A0() {
        return Build.VERSION.SDK_INT >= 29;
    }

    /* renamed from: A1 */
    public static final void m2376A1(@NotNull TextView textView, @Nullable String str, @Nullable String str2, @NotNull Function1<? super String, Unit> onClick) {
        Intrinsics.checkNotNullParameter(textView, "textView");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        textView.setMovementMethod(LinkMovementMethod.getInstance());
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(str);
        ForegroundColorSpan foregroundColorSpan = new ForegroundColorSpan(Color.rgb(86, 119, 255));
        int length = spannableStringBuilder.toString().length();
        spannableStringBuilder.append((CharSequence) str2);
        int length2 = spannableStringBuilder.toString().length();
        spannableStringBuilder.setSpan(new C0845f0(str2, new c(onClick)), length, length2, 33);
        spannableStringBuilder.setSpan(new UnderlineSpan(), 8, 12, 34);
        spannableStringBuilder.setSpan(foregroundColorSpan, length, length2, 33);
        textView.setText(spannableStringBuilder);
    }

    /* renamed from: B */
    public static /* synthetic */ void m2377B(View view, long j2, Function1 function1, int i2) {
        if ((i2 & 1) != 0) {
            j2 = 1000;
        }
        m2380C(view, j2, function1);
    }

    /* renamed from: B0 */
    public static boolean m2378B0() {
        return Build.VERSION.SDK_INT >= 30;
    }

    /* renamed from: B1 */
    public static void m2379B1(String str) {
        MyApp myApp = MyApp.f9894i;
        Typeface typeface = C4325a.f11166a;
        C4325a.m4898a(myApp, str, null, ContextCompat.getColor(myApp, R$color.normalColor), ContextCompat.getColor(myApp, R$color.defaultTextColor), 0, false, true).show();
    }

    /* renamed from: C */
    public static final <T extends View> void m2380C(@NotNull final T t, long j2, @NotNull final Function1<? super T, Unit> block) {
        Intrinsics.checkNotNullParameter(t, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        t.setTag(1123461123, Long.valueOf(j2));
        t.setOnClickListener(new View.OnClickListener() { // from class: b.w.b.d.a
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                long j3;
                long j4;
                boolean z;
                View this_clickWithTrigger = t;
                Function1 block2 = block;
                Intrinsics.checkNotNullParameter(this_clickWithTrigger, "$this_clickWithTrigger");
                Intrinsics.checkNotNullParameter(block2, "$block");
                long currentTimeMillis = System.currentTimeMillis();
                if (this_clickWithTrigger.getTag(1123460103) != null) {
                    Object tag = this_clickWithTrigger.getTag(1123460103);
                    Objects.requireNonNull(tag, "null cannot be cast to non-null type kotlin.Long");
                    j3 = ((Long) tag).longValue();
                } else {
                    j3 = -601;
                }
                long j5 = currentTimeMillis - j3;
                if (this_clickWithTrigger.getTag(1123461123) != null) {
                    Object tag2 = this_clickWithTrigger.getTag(1123461123);
                    Objects.requireNonNull(tag2, "null cannot be cast to non-null type kotlin.Long");
                    j4 = ((Long) tag2).longValue();
                } else {
                    j4 = 600;
                }
                if (j5 >= j4) {
                    z = true;
                    this_clickWithTrigger.setTag(1123460103, Long.valueOf(currentTimeMillis));
                } else {
                    z = false;
                }
                if (z) {
                    Objects.requireNonNull(view, "null cannot be cast to non-null type T of com.qunidayede.supportlibrary.utils.ViewClickDelayKt.clickWithTrigger$lambda-1");
                    block2.invoke(view);
                }
            }
        });
    }

    /* renamed from: C0 */
    public static boolean m2381C0() {
        return Build.VERSION.SDK_INT >= 31;
    }

    /* renamed from: C1 */
    public static void m2382C1(boolean z, View view, int i2, long j2) {
        ValueAnimator ofInt = z ? ValueAnimator.ofInt(0, i2) : ValueAnimator.ofInt(i2, 0);
        ofInt.addUpdateListener(new b(view));
        ofInt.setDuration(j2);
        ofInt.start();
    }

    /* renamed from: D */
    public static final int m2383D(int i2) {
        C0839c0 c0839c0 = C0839c0.f232a;
        try {
            return ResourcesCompat.getColor((Resources) C0839c0.f233b.getValue(), i2, null);
        } catch (Resources.NotFoundException unused) {
            return 0;
        }
    }

    /* renamed from: D0 */
    public static boolean m2384D0() {
        return Build.VERSION.SDK_INT >= 33;
    }

    @NotNull
    /* renamed from: D1 */
    public static final InterfaceC4762x m2385D1(@NotNull OutputStream sink) {
        Logger logger = C4754p.f12154a;
        Intrinsics.checkNotNullParameter(sink, "$this$sink");
        return new C4756r(sink, new C4737a0());
    }

    /* renamed from: E */
    public static int m2386E(int i2, int i3) {
        int i4 = i2 - i3;
        if (i4 > i3) {
            i4 = i3;
            i3 = i4;
        }
        int i5 = 1;
        int i6 = 1;
        while (i2 > i3) {
            i5 *= i2;
            if (i6 <= i4) {
                i5 /= i6;
                i6++;
            }
            i2--;
        }
        while (i6 <= i4) {
            i5 /= i6;
            i6++;
        }
        return i5;
    }

    /* renamed from: E0 */
    public static boolean m2387E0() {
        return Build.VERSION.SDK_INT >= 34;
    }

    @NotNull
    /* renamed from: E1 */
    public static final InterfaceC4762x m2388E1(@NotNull Socket sink) {
        Logger logger = C4754p.f12154a;
        Intrinsics.checkNotNullParameter(sink, "$this$sink");
        C4763y c4763y = new C4763y(sink);
        OutputStream outputStream = sink.getOutputStream();
        Intrinsics.checkNotNullExpressionValue(outputStream, "getOutputStream()");
        C4756r sink2 = new C4756r(outputStream, c4763y);
        Intrinsics.checkNotNullParameter(sink2, "sink");
        return new C4741c(c4763y, sink2);
    }

    /* renamed from: F */
    public static int m2389F(String str, String str2) {
        if (str.equals(str2)) {
            return 0;
        }
        String[] split = str.split("\\.");
        String[] split2 = str2.split("\\.");
        int length = split.length;
        int length2 = split2.length;
        int min = Math.min(split.length, split2.length);
        String str3 = split[0];
        int i2 = 0;
        int i3 = 0;
        while (i2 < min) {
            i3 = Integer.parseInt(split[i2]) - Integer.parseInt(split2[i2]);
            if (i3 != 0) {
                break;
            }
            i2++;
        }
        if (i3 != 0) {
            return i3 > 0 ? 1 : -1;
        }
        for (int i4 = i2; i4 < split.length; i4++) {
            if (Integer.parseInt(split[i4]) > 0) {
                return 1;
            }
        }
        while (i2 < split2.length) {
            if (Integer.parseInt(split2[i2]) > 0) {
                return -1;
            }
            i2++;
        }
        return 0;
    }

    /* renamed from: F0 */
    public static boolean m2390F0() {
        return Build.VERSION.SDK_INT >= 23;
    }

    /* renamed from: F1 */
    public static InterfaceC4762x m2391F1(File sink, boolean z, int i2, Object obj) {
        Logger logger = C4754p.f12154a;
        if ((i2 & 1) != 0) {
            z = false;
        }
        Intrinsics.checkNotNullParameter(sink, "$this$sink");
        return m2385D1(new FileOutputStream(sink, z));
    }

    /* renamed from: G */
    public static int m2392G(String str, String str2) {
        int glCreateProgram = GLES20.glCreateProgram();
        m2527x();
        m2468e(35633, str, glCreateProgram);
        m2468e(35632, str2, glCreateProgram);
        GLES20.glLinkProgram(glCreateProgram);
        int[] iArr = {0};
        GLES20.glGetProgramiv(glCreateProgram, 35714, iArr, 0);
        if (iArr[0] != 1) {
            GLES20.glGetProgramInfoLog(glCreateProgram);
        }
        m2527x();
        return glCreateProgram;
    }

    /* renamed from: G0 */
    public static boolean m2393G0() {
        return Build.VERSION.SDK_INT >= 26;
    }

    @NotNull
    /* renamed from: G1 */
    public static final InterfaceC4764z m2394G1(@NotNull File source) {
        Logger logger = C4754p.f12154a;
        Intrinsics.checkNotNullParameter(source, "$this$source");
        return m2397H1(new FileInputStream(source));
    }

    /* renamed from: H */
    public static long m2395H(InputStream inputStream, OutputStream outputStream, boolean z) {
        byte[] bArr = new byte[8192];
        long j2 = 0;
        while (true) {
            try {
                int read = inputStream.read(bArr);
                if (read == -1) {
                    break;
                }
                if (read > 0) {
                    j2 += read;
                    if (outputStream != null) {
                        outputStream.write(bArr, 0, read);
                    }
                }
            } finally {
            }
        }
        if (outputStream != null) {
            if (z) {
                outputStream.close();
            } else {
                outputStream.flush();
            }
            outputStream = null;
        }
        inputStream.close();
        int i2 = C4786c.f12262a;
        if (z && outputStream != null) {
            try {
                outputStream.close();
            } catch (IOException unused) {
            }
        }
        return j2;
    }

    /* renamed from: H0 */
    public static boolean m2396H0() {
        return Build.VERSION.SDK_INT >= 28;
    }

    @NotNull
    /* renamed from: H1 */
    public static final InterfaceC4764z m2397H1(@NotNull InputStream source) {
        Logger logger = C4754p.f12154a;
        Intrinsics.checkNotNullParameter(source, "$this$source");
        return new C4753o(source, new C4737a0());
    }

    /* renamed from: I */
    public static final void m2398I(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Object systemService = C4195m.m4792Y().getSystemService("clipboard");
        Objects.requireNonNull(systemService, "null cannot be cast to non-null type android.content.ClipboardManager");
        ((ClipboardManager) systemService).setPrimaryClip(ClipData.newPlainText("share", str));
        Application m4792Y = C4195m.m4792Y();
        Typeface typeface = C4325a.f11166a;
        C4325a.m4903f(m4792Y, m4792Y.getString(R.string.clip_success), 0, true).show();
    }

    /* renamed from: I0 */
    public static final boolean m2399I0(@NotNull AssertionError isAndroidGetsocknameError) {
        Logger logger = C4754p.f12154a;
        Intrinsics.checkNotNullParameter(isAndroidGetsocknameError, "$this$isAndroidGetsocknameError");
        if (isAndroidGetsocknameError.getCause() == null) {
            return false;
        }
        String message = isAndroidGetsocknameError.getMessage();
        return message != null ? StringsKt__StringsKt.contains$default((CharSequence) message, (CharSequence) "getsockname failed", false, 2, (Object) null) : false;
    }

    @NotNull
    /* renamed from: I1 */
    public static final InterfaceC4764z m2400I1(@NotNull Socket source) {
        Logger logger = C4754p.f12154a;
        Intrinsics.checkNotNullParameter(source, "$this$source");
        C4763y c4763y = new C4763y(source);
        InputStream inputStream = source.getInputStream();
        Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream()");
        C4753o source2 = new C4753o(inputStream, c4763y);
        Intrinsics.checkNotNullParameter(source2, "source");
        return new C4742d(c4763y, source2);
    }

    @Nullable
    /* renamed from: J */
    public static final <R> Object m2401J(@NotNull Function2<? super InterfaceC3055e0, ? super Continuation<? super R>, ? extends Object> function2, @NotNull Continuation<? super R> continuation) {
        C2968q c2968q = new C2968q(continuation.get$context(), continuation);
        Object m2406K1 = m2406K1(c2968q, c2968q, function2);
        if (m2406K1 == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
            DebugProbesKt.probeCoroutineSuspended(continuation);
        }
        return m2406K1;
    }

    /* renamed from: J0 */
    public static final boolean m2402J0(int i2) {
        return i2 == 1 || i2 == 2;
    }

    /* renamed from: J1 */
    public static void m2403J1(Function2 function2, Object obj, Continuation continuation, Function1 function1, int i2) {
        int i3 = i2 & 4;
        try {
            Continuation intercepted = IntrinsicsKt__IntrinsicsJvmKt.intercepted(IntrinsicsKt__IntrinsicsJvmKt.createCoroutineUnintercepted(function2, obj, continuation));
            Result.Companion companion = Result.INSTANCE;
            C2958g.m3421a(intercepted, Result.m6055constructorimpl(Unit.INSTANCE), null);
        } catch (Throwable th) {
            Result.Companion companion2 = Result.INSTANCE;
            continuation.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(th)));
        }
    }

    /* renamed from: K */
    public static FloatBuffer m2404K(float[] fArr) {
        return (FloatBuffer) ByteBuffer.allocateDirect(fArr.length * 4).order(ByteOrder.nativeOrder()).asFloatBuffer().put(fArr).flip();
    }

    /* renamed from: K0 */
    public static boolean m2405K0(CharSequence charSequence) {
        return charSequence == null || charSequence.length() == 0;
    }

    @Nullable
    /* renamed from: K1 */
    public static final <T, R> Object m2406K1(@NotNull C2968q<? super T> c2968q, R r, @NotNull Function2<? super R, ? super Continuation<? super T>, ? extends Object> function2) {
        Object c3108w;
        Object m3580T;
        c2968q.m3508i0();
        try {
        } catch (Throwable th) {
            c3108w = new C3108w(th, false, 2);
        }
        if (function2 == null) {
            throw new NullPointerException("null cannot be cast to non-null type (R, kotlin.coroutines.Continuation<T>) -> kotlin.Any?");
        }
        c3108w = ((Function2) TypeIntrinsics.beforeCheckcastToFunctionOfArity(function2, 2)).invoke(r, c2968q);
        if (c3108w != IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() && (m3580T = c2968q.m3580T(c3108w)) != C3071j1.f8418b) {
            if (m3580T instanceof C3108w) {
                throw ((C3108w) m3580T).f8470b;
            }
            return C3071j1.m3618a(m3580T);
        }
        return IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
    }

    /* renamed from: L */
    public static final Drawable m2407L(View view) {
        view.measure(View.MeasureSpec.makeMeasureSpec(0, 0), View.MeasureSpec.makeMeasureSpec(0, 0));
        view.layout(0, 0, view.getMeasuredWidth(), view.getMeasuredHeight());
        Bitmap bitmap = Bitmap.createBitmap(view.getMeasuredWidth(), view.getMeasuredHeight(), Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(bitmap);
        view.draw(canvas);
        canvas.save();
        Intrinsics.checkNotNullExpressionValue(bitmap, "bitmap");
        BitmapDrawable bitmapDrawable = new BitmapDrawable(Resources.getSystem(), bitmap);
        bitmapDrawable.setBounds(0, 0, view.getWidth(), view.getHeight());
        return bitmapDrawable;
    }

    /* renamed from: L0 */
    public static boolean m2408L0(XmlPullParser xmlPullParser, String str) {
        return (xmlPullParser.getEventType() == 3) && xmlPullParser.getName().equals(str);
    }

    /* renamed from: L1 */
    public static void m2409L1(String str) {
        C4325a.m4902e(MyApp.f9894i, str).show();
    }

    @androidx.annotation.Nullable
    /* renamed from: M */
    public static Bitmap m2410M(String str, int i2, int i3) {
        if (TextUtils.isEmpty(str) || i2 < 0 || i3 < 0) {
            return null;
        }
        try {
            Hashtable hashtable = new Hashtable();
            if (!TextUtils.isEmpty("UTF-8")) {
                hashtable.put(EnumC2524f.CHARACTER_SET, "UTF-8");
            }
            if (!TextUtils.isEmpty("H")) {
                hashtable.put(EnumC2524f.ERROR_CORRECTION, "H");
            }
            if (!TextUtils.isEmpty("2")) {
                hashtable.put(EnumC2524f.MARGIN, "2");
            }
            C2544b m2868a = new C2499b().m2868a(str, EnumC2497a.QR_CODE, i2, i3, hashtable);
            int[] iArr = new int[i2 * i3];
            for (int i4 = 0; i4 < i3; i4++) {
                for (int i5 = 0; i5 < i2; i5++) {
                    if (m2868a.m2958c(i5, i4)) {
                        iArr[(i4 * i2) + i5] = -16777216;
                    } else {
                        iArr[(i4 * i2) + i5] = -1;
                    }
                }
            }
            Bitmap createBitmap = Bitmap.createBitmap(i2, i3, Bitmap.Config.ARGB_8888);
            createBitmap.setPixels(iArr, 0, i2, 0, 0, i2, i3);
            return createBitmap;
        } catch (Exception e2) {
            e2.printStackTrace();
            return null;
        }
    }

    /* renamed from: M0 */
    public static boolean m2411M0(Context context) {
        NetworkInfo[] allNetworkInfo;
        ConnectivityManager connectivityManager = (ConnectivityManager) context.getApplicationContext().getSystemService("connectivity");
        if (connectivityManager != null && (allNetworkInfo = connectivityManager.getAllNetworkInfo()) != null && allNetworkInfo.length > 0) {
            for (NetworkInfo networkInfo : allNetworkInfo) {
                if (networkInfo.getState() == NetworkInfo.State.CONNECTED) {
                    return true;
                }
            }
        }
        return false;
    }

    /* renamed from: M1 */
    public static int m2412M1(int[] iArr) {
        int i2 = 0;
        for (int i3 : iArr) {
            i2 += i3;
        }
        return i2;
    }

    /* renamed from: N */
    public static final SpannableStringBuilder m2413N(TextView textView, int i2) {
        int length = textView.getText().length();
        if (i2 <= length) {
            return new SpannableStringBuilder(textView.getText());
        }
        throw new IndexOutOfBoundsException(C1499a.m629o("下标越界，当前文字长度:", length, ",position:", i2));
    }

    /* renamed from: N0 */
    public static final boolean m2414N0(@Nullable List<? extends Object> list) {
        return !(list == null || list.isEmpty());
    }

    /* renamed from: N1 */
    public static final int m2415N1(@NotNull String str, int i2, int i3, int i4) {
        return (int) m2418O1(str, i2, i3, i4);
    }

    /* renamed from: O */
    public static int m2416O(byte[] bArr, OutputStream outputStream) {
        int i2 = 0;
        int length = bArr.length + 0;
        int i3 = 0;
        while (i2 < length) {
            int i4 = i2 + 1;
            int i5 = bArr[i2];
            if (i5 == 95) {
                outputStream.write(32);
            } else if (i5 == 61) {
                int i6 = i4 + 1;
                if (i6 >= length) {
                    throw new IOException("Invalid quoted printable encoding; truncated escape sequence");
                }
                byte b2 = bArr[i4];
                int i7 = i6 + 1;
                byte b3 = bArr[i6];
                if (b2 != 13) {
                    outputStream.write(m2522v0(b3) | (m2522v0(b2) << 4));
                    i3++;
                } else if (b3 != 10) {
                    throw new IOException("Invalid quoted printable encoding; CR must be followed by LF");
                }
                i2 = i7;
            } else {
                outputStream.write(i5);
                i3++;
            }
            i2 = i4;
        }
        return i3;
    }

    /* renamed from: O0 */
    public static final boolean m2417O0(@NotNull C4744f isProbablyUtf8) {
        Intrinsics.checkParameterIsNotNull(isProbablyUtf8, "$this$isProbablyUtf8");
        try {
            C4744f c4744f = new C4744f();
            isProbablyUtf8.m5392t(c4744f, 0L, RangesKt___RangesKt.coerceAtMost(isProbablyUtf8.f12133e, 64L));
            for (int i2 = 0; i2 < 16; i2++) {
                if (c4744f.mo5387m()) {
                    return true;
                }
                int m5367U = c4744f.m5367U();
                if (Character.isISOControl(m5367U) && !Character.isWhitespace(m5367U)) {
                    return false;
                }
            }
            return true;
        } catch (EOFException unused) {
            return false;
        }
    }

    /* renamed from: O1 */
    public static final long m2418O1(@NotNull String str, long j2, long j3, long j4) {
        String m2421P1 = m2421P1(str);
        if (m2421P1 == null) {
            return j2;
        }
        Long longOrNull = StringsKt__StringNumberConversionsKt.toLongOrNull(m2421P1);
        if (longOrNull == null) {
            throw new IllegalStateException(("System property '" + str + "' has unrecognized value '" + m2421P1 + '\'').toString());
        }
        long longValue = longOrNull.longValue();
        if (j3 <= longValue && j4 >= longValue) {
            return longValue;
        }
        throw new IllegalStateException(("System property '" + str + "' should be in range " + j3 + ".." + j4 + ", but is '" + longValue + '\'').toString());
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x00ea, code lost:
    
        return null;
     */
    /* JADX WARN: Removed duplicated region for block: B:15:0x00be  */
    /* renamed from: P */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.net.InetAddress m2419P(java.lang.String r20, int r21, int r22) {
        /*
            Method dump skipped, instructions count: 259
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p250p1.C2354n.m2419P(java.lang.String, int, int):java.net.InetAddress");
    }

    /* renamed from: P0 */
    public static boolean m2420P0(XmlPullParser xmlPullParser) {
        return xmlPullParser.getEventType() == 2;
    }

    @Nullable
    /* renamed from: P1 */
    public static final String m2421P1(@NotNull String str) {
        int i2 = C2971t.f8136a;
        try {
            return System.getProperty(str);
        } catch (SecurityException unused) {
            return null;
        }
    }

    @Nullable
    /* renamed from: Q */
    public static final Object m2422Q(long j2, @NotNull Continuation<? super Unit> continuation) {
        if (j2 <= 0) {
            return Unit.INSTANCE;
        }
        C3069j c3069j = new C3069j(IntrinsicsKt__IntrinsicsJvmKt.intercepted(continuation), 1);
        c3069j.m3602A();
        if (j2 < Long.MAX_VALUE) {
            CoroutineContext.Element element = c3069j.f8415i.get(ContinuationInterceptor.INSTANCE);
            if (!(element instanceof InterfaceC3070j0)) {
                element = null;
            }
            InterfaceC3070j0 interfaceC3070j0 = (InterfaceC3070j0) element;
            if (interfaceC3070j0 == null) {
                interfaceC3070j0 = C3064h0.f8402a;
            }
            interfaceC3070j0.mo3617e(j2, c3069j);
        }
        Object m3612u = c3069j.m3612u();
        if (m3612u == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
            DebugProbesKt.probeCoroutineSuspended(continuation);
        }
        return m3612u;
    }

    /* renamed from: Q0 */
    public static boolean m2423Q0(XmlPullParser xmlPullParser, String str) {
        return m2420P0(xmlPullParser) && xmlPullParser.getName().equals(str);
    }

    /* renamed from: Q1 */
    public static /* synthetic */ int m2424Q1(String str, int i2, int i3, int i4, int i5, Object obj) {
        if ((i5 & 4) != 0) {
            i3 = 1;
        }
        if ((i5 & 8) != 0) {
            i4 = Integer.MAX_VALUE;
        }
        return m2415N1(str, i2, i3, i4);
    }

    /* renamed from: R */
    public static int m2425R(Context context, float f2) {
        return (int) ((f2 * context.getResources().getDisplayMetrics().density) + 0.5f);
    }

    /* renamed from: R0 */
    public static void m2426R0(boolean z, String str) {
        if (!z) {
            throw new IllegalArgumentException(str);
        }
    }

    /* renamed from: R1 */
    public static /* synthetic */ long m2427R1(String str, long j2, long j3, long j4, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            j3 = 1;
        }
        long j5 = j3;
        if ((i2 & 8) != 0) {
            j4 = Long.MAX_VALUE;
        }
        return m2418O1(str, j2, j5, j4);
    }

    /* renamed from: S */
    public static float m2428S(float f2, float f3, float f4, float f5) {
        double d2 = f2 - f4;
        double d3 = f3 - f5;
        return (float) Math.sqrt((d3 * d3) + (d2 * d2));
    }

    /* renamed from: S0 */
    public static boolean m2429S0(byte[] bArr, int i2, int i3) {
        int min = Math.min(i3, bArr.length);
        for (int max = Math.max(i2, 0); max < min; max++) {
            if (bArr[max] == 1) {
                return false;
            }
        }
        return true;
    }

    /* renamed from: S1 */
    public static void m2430S1(Throwable th) {
        if (th instanceof VirtualMachineError) {
            throw ((VirtualMachineError) th);
        }
        if (th instanceof ThreadDeath) {
            throw ((ThreadDeath) th);
        }
        if (th instanceof LinkageError) {
            throw ((LinkageError) th);
        }
    }

    /* renamed from: T */
    public static float m2431T(int i2, int i3, int i4, int i5) {
        double d2 = i2 - i4;
        double d3 = i3 - i5;
        return (float) Math.sqrt((d3 * d3) + (d2 * d2));
    }

    /* renamed from: T0 */
    public static boolean m2432T0(byte[][] bArr, int i2, int i3, int i4) {
        int min = Math.min(i4, bArr.length);
        for (int max = Math.max(i3, 0); max < min; max++) {
            if (bArr[max][i2] == 1) {
                return false;
            }
        }
        return true;
    }

    @Nullable
    /* renamed from: T1 */
    public static final String m2433T1(@NotNull String toCanonicalHost) {
        Intrinsics.checkParameterIsNotNull(toCanonicalHost, "$this$toCanonicalHost");
        int i2 = 0;
        int i3 = -1;
        if (!StringsKt__StringsKt.contains$default((CharSequence) toCanonicalHost, (CharSequence) ":", false, 2, (Object) null)) {
            try {
                String ascii = IDN.toASCII(toCanonicalHost);
                Intrinsics.checkExpressionValueIsNotNull(ascii, "IDN.toASCII(host)");
                Locale locale = Locale.US;
                Intrinsics.checkExpressionValueIsNotNull(locale, "Locale.US");
                if (ascii == null) {
                    throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
                }
                String lowerCase = ascii.toLowerCase(locale);
                Intrinsics.checkExpressionValueIsNotNull(lowerCase, "(this as java.lang.String).toLowerCase(locale)");
                if (lowerCase.length() == 0) {
                    return null;
                }
                int length = lowerCase.length();
                for (int i4 = 0; i4 < length; i4++) {
                    char charAt = lowerCase.charAt(i4);
                    if (charAt > 31 && charAt < 127 && StringsKt__StringsKt.indexOf$default((CharSequence) " #%/:?@[\\]", charAt, 0, false, 6, (Object) null) == -1) {
                    }
                    i2 = 1;
                    break;
                }
                if (i2 != 0) {
                    return null;
                }
                return lowerCase;
            } catch (IllegalArgumentException unused) {
                return null;
            }
        }
        InetAddress m2419P = (StringsKt__StringsJVMKt.startsWith$default(toCanonicalHost, "[", false, 2, null) && StringsKt__StringsJVMKt.endsWith$default(toCanonicalHost, "]", false, 2, null)) ? m2419P(toCanonicalHost, 1, toCanonicalHost.length() - 1) : m2419P(toCanonicalHost, 0, toCanonicalHost.length());
        if (m2419P == null) {
            return null;
        }
        byte[] address = m2419P.getAddress();
        if (address.length != 16) {
            if (address.length == 4) {
                return m2419P.getHostAddress();
            }
            throw new AssertionError("Invalid IPv6 address: '" + toCanonicalHost + '\'');
        }
        Intrinsics.checkExpressionValueIsNotNull(address, "address");
        int i5 = 0;
        int i6 = 0;
        while (i5 < address.length) {
            int i7 = i5;
            while (i7 < 16 && address[i7] == 0 && address[i7 + 1] == 0) {
                i7 += 2;
            }
            int i8 = i7 - i5;
            if (i8 > i6 && i8 >= 4) {
                i3 = i5;
                i6 = i8;
            }
            i5 = i7 + 2;
        }
        C4744f c4744f = new C4744f();
        while (i2 < address.length) {
            if (i2 == i3) {
                c4744f.m5374a0(58);
                i2 += i6;
                if (i2 == 16) {
                    c4744f.m5374a0(58);
                }
            } else {
                if (i2 > 0) {
                    c4744f.m5374a0(58);
                }
                byte b2 = address[i2];
                byte[] bArr = C4401c.f11556a;
                c4744f.mo5397z(((b2 & 255) << 8) | (address[i2 + 1] & 255));
                i2 += 2;
            }
        }
        return c4744f.m5365S();
    }

    /* renamed from: U */
    public static int m2434U(float f2, Context context) {
        if (f6087a == 0.0f) {
            f6087a = context.getResources().getDisplayMetrics().density;
        }
        return (int) (f2 * f6087a);
    }

    /* renamed from: U0 */
    public static InterfaceC3053d1 m2435U0(InterfaceC3055e0 interfaceC3055e0, CoroutineContext coroutineContext, int i2, Function2 function2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            coroutineContext = EmptyCoroutineContext.INSTANCE;
        }
        if ((i3 & 2) != 0) {
            i2 = 1;
        }
        CoroutineContext m3455a = C2976a0.m3455a(interfaceC3055e0, coroutineContext);
        C1345b.m352d(i2);
        C3098s1 c3074k1 = i2 == 2 ? new C3074k1(m3455a, function2) : new C3098s1(m3455a, true);
        c3074k1.m3512m0(i2, c3074k1, function2);
        return c3074k1;
    }

    @NotNull
    /* renamed from: U1 */
    public static final String m2436U1(@NotNull Continuation<?> continuation) {
        Object m6055constructorimpl;
        if (continuation instanceof C2957f) {
            return continuation.toString();
        }
        try {
            Result.Companion companion = Result.INSTANCE;
            m6055constructorimpl = Result.m6055constructorimpl(continuation + '@' + m2495m0(continuation));
        } catch (Throwable th) {
            Result.Companion companion2 = Result.INSTANCE;
            m6055constructorimpl = Result.m6055constructorimpl(ResultKt.createFailure(th));
        }
        if (Result.m6058exceptionOrNullimpl(m6055constructorimpl) != null) {
            m6055constructorimpl = continuation.getClass().getName() + '@' + m2495m0(continuation);
        }
        return (String) m6055constructorimpl;
    }

    /* renamed from: V */
    public static int m2437V(Context context, double d2) {
        return Math.round(((float) d2) * context.getResources().getDisplayMetrics().density);
    }

    /* renamed from: V0 */
    public static void m2438V0(InterfaceC3006b interfaceC3006b, InterfaceC2846i base, boolean z, Function1 function1, Function1 callback, int i2) {
        boolean z2 = (i2 & 2) != 0 ? false : z;
        if ((i2 & 4) != 0) {
            function1 = null;
        }
        Function1 function12 = function1;
        Intrinsics.checkNotNullParameter(interfaceC3006b, "<this>");
        Intrinsics.checkNotNullParameter(base, "base");
        Intrinsics.checkNotNullParameter(callback, "callback");
        LifecycleCoroutineScope scope = base.scope();
        C3079m0 c3079m0 = C3079m0.f8432c;
        m2435U0(scope, C2964m.f8127b, 0, new C2832a(interfaceC3006b, function12, z2, base, callback, null), 2, null);
    }

    @NotNull
    /* renamed from: V1 */
    public static final String m2439V1(byte b2) {
        char[] cArr = C4740b.f12127a;
        return new String(new char[]{cArr[(b2 >> 4) & 15], cArr[b2 & 15]});
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0076 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0082 A[Catch: all -> 0x005d, TryCatch #2 {all -> 0x005d, blocks: (B:12:0x0036, B:20:0x007e, B:22:0x0082, B:24:0x0086, B:30:0x0094, B:31:0x0095, B:32:0x00a0, B:33:0x00a1, B:35:0x00a5, B:38:0x00b8, B:39:0x00c3, B:53:0x0059), top: B:7:0x0022 }] */
    /* JADX WARN: Removed duplicated region for block: B:33:0x00a1 A[Catch: all -> 0x005d, TryCatch #2 {all -> 0x005d, blocks: (B:12:0x0036, B:20:0x007e, B:22:0x0082, B:24:0x0086, B:30:0x0094, B:31:0x0095, B:32:0x00a0, B:33:0x00a1, B:35:0x00a5, B:38:0x00b8, B:39:0x00c3, B:53:0x0059), top: B:7:0x0022 }] */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0060  */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0024  */
    /* JADX WARN: Type inference failed for: r10v0, types: [boolean] */
    /* JADX WARN: Type inference failed for: r10v1, types: [c.a.a2.q] */
    /* JADX WARN: Type inference failed for: r10v4 */
    /* JADX WARN: Type inference failed for: r2v1, types: [c.a.b2.c, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r2v11 */
    /* JADX WARN: Type inference failed for: r2v3 */
    /* JADX WARN: Type inference failed for: r9v1 */
    /* JADX WARN: Type inference failed for: r9v4 */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:36:0x00b5 -> B:13:0x0039). Please report as a decompilation issue!!! */
    @org.jetbrains.annotations.Nullable
    /* renamed from: W */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final <T> java.lang.Object m2440W(@org.jetbrains.annotations.NotNull p379c.p380a.p383b2.InterfaceC3007c<? super T> r8, @org.jetbrains.annotations.NotNull p379c.p380a.p382a2.InterfaceC2994q<? extends T> r9, boolean r10, @org.jetbrains.annotations.NotNull kotlin.coroutines.Continuation<? super kotlin.Unit> r11) {
        /*
            Method dump skipped, instructions count: 208
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p250p1.C2354n.m2440W(c.a.b2.c, c.a.a2.q, boolean, kotlin.coroutines.Continuation):java.lang.Object");
    }

    /* renamed from: W0 */
    public static void m2441W0(InterfaceC3006b interfaceC3006b, InterfaceC2846i base, Function1 callback, boolean z, Function1 function1, int i2) {
        boolean z2 = (i2 & 4) != 0 ? false : z;
        Function1 function12 = (i2 & 8) != 0 ? null : function1;
        Intrinsics.checkNotNullParameter(interfaceC3006b, "<this>");
        Intrinsics.checkNotNullParameter(base, "base");
        Intrinsics.checkNotNullParameter(callback, "callback");
        LifecycleCoroutineScope scope = base.scope();
        C3079m0 c3079m0 = C3079m0.f8432c;
        m2435U0(scope, C2964m.f8127b, 0, new C2834c(interfaceC3006b, base, z2, function12, callback, null), 2, null);
    }

    /* renamed from: W1 */
    public static final float m2442W1(float f2) {
        MyApp myApp = MyApp.f9891f;
        return TypedValue.applyDimension(1, f2, MyApp.m4183d().getResources().getDisplayMetrics());
    }

    /* renamed from: X */
    public static void m2443X() {
        if (C2344d0.f6035a >= 18) {
            Trace.endSection();
        }
    }

    /* renamed from: X0 */
    public static void m2444X0(InterfaceC3006b interfaceC3006b, BaseViewModel baseViewModel, boolean z, Function1 function1, Function1 callback, int i2) {
        boolean z2 = (i2 & 2) != 0 ? false : z;
        Intrinsics.checkNotNullParameter(interfaceC3006b, "<this>");
        Intrinsics.checkNotNullParameter(baseViewModel, "baseViewModel");
        Intrinsics.checkNotNullParameter(callback, "callback");
        InterfaceC3055e0 viewModelScope = ViewModelKt.getViewModelScope(baseViewModel);
        C3079m0 c3079m0 = C3079m0.f8432c;
        m2435U0(viewModelScope, C2964m.f8127b, 0, new C2835d(interfaceC3006b, baseViewModel, null, z2, callback, null), 2, null);
    }

    @NotNull
    /* renamed from: X1 */
    public static final AbstractC4387j0 m2445X1(@Nullable HashMap<String, ? extends Object> hashMap) {
        byte[] toRequestBody;
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        if (!(hashMap == null || hashMap.isEmpty())) {
            linkedHashMap.put("data", hashMap);
        }
        linkedHashMap.put("deviceId", C0887j.m211a());
        StringBuilder sb = new StringBuilder();
        MyApp myApp = MyApp.f9891f;
        TokenBean m4186g = MyApp.m4186g();
        sb.append((Object) (m4186g == null ? null : m4186g.token));
        sb.append('_');
        TokenBean m4186g2 = MyApp.m4186g();
        sb.append((Object) (m4186g2 == null ? null : m4186g2.user_id));
        linkedHashMap.put("token", sb.toString());
        Type type = new a().getType();
        Intrinsics.checkNotNullExpressionValue(type, "object : TypeToken<HashMap<String, Any>>() {}.type");
        String params = new C2480j().m2854h(linkedHashMap, type);
        Intrinsics.checkNotNullExpressionValue(params, "params");
        m2454a1(params);
        byte[] bytes = params.getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec("67f69826eac1a4f1".getBytes(), "AES-128-ECB");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(1, secretKeySpec);
            toRequestBody = cipher.doFinal(bytes);
        } catch (Exception e2) {
            System.out.println(e2.toString());
            toRequestBody = null;
        }
        Intrinsics.checkNotNullExpressionValue(toRequestBody, "AesSecurity().encryptOrigin(\n        params.toByteArray(), NetConfig.AES_KEY\n    )");
        C4371b0.a aVar = C4371b0.f11309c;
        C4371b0 m4945a = (1 & 6) == 0 ? C4371b0.a.m4945a("multipart/form-data") : null;
        int length = (6 & 4) != 0 ? toRequestBody.length : 0;
        Intrinsics.checkParameterIsNotNull(toRequestBody, "$this$toRequestBody");
        C4401c.m5018c(toRequestBody.length, 0, length);
        return new C4385i0(toRequestBody, m4945a, length, 0);
    }

    /* renamed from: Y */
    public static boolean m2446Y(Object obj, Object obj2) {
        return obj == null ? obj2 == null : obj.equals(obj2);
    }

    /* renamed from: Y0 */
    public static void m2447Y0(InterfaceC3006b interfaceC3006b, InterfaceC2846i base, PageRefreshLayout refreshLayout, BindingAdapter bindingAdapter, int i2) {
        Intrinsics.checkNotNullParameter(interfaceC3006b, "<this>");
        Intrinsics.checkNotNullParameter(base, "base");
        Intrinsics.checkNotNullParameter(refreshLayout, "refreshLayout");
        LifecycleCoroutineScope scope = base.scope();
        C3079m0 c3079m0 = C3079m0.f8432c;
        m2435U0(scope, C2964m.f8127b, 0, new C2837f(interfaceC3006b, refreshLayout, base, null, null), 2, null);
    }

    @Nullable
    /* renamed from: Y1 */
    public static final <T> Object m2448Y1(@NotNull Object obj, @Nullable Function1<? super Throwable, Unit> function1) {
        Throwable m6058exceptionOrNullimpl = Result.m6058exceptionOrNullimpl(obj);
        return m6058exceptionOrNullimpl == null ? function1 != null ? new C3111x(obj, function1) : obj : new C3108w(m6058exceptionOrNullimpl, false, 2);
    }

    /* renamed from: Z */
    public static void m2449Z(String str) {
        C4325a.m4899b(MyApp.f9894i, str).show();
    }

    /* renamed from: Z0 */
    public static final void m2450Z0(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        C1535e.m691d(3, C1535e.f1719d.m694a(), str);
    }

    /* renamed from: Z1 */
    public static void m2451Z1(String str) {
        C4325a.m4904g(MyApp.f9894i, str).show();
    }

    /* renamed from: a */
    public static InterfaceC2983f m2452a(int i2, EnumC2982e enumC2982e, Function1 function1, int i3) {
        EnumC2982e enumC2982e2 = EnumC2982e.SUSPEND;
        if ((i3 & 1) != 0) {
            i2 = 0;
        }
        if ((i3 & 2) != 0) {
            enumC2982e = enumC2982e2;
        }
        int i4 = i3 & 4;
        int i5 = 1;
        if (i2 == -2) {
            if (enumC2982e == enumC2982e2) {
                Objects.requireNonNull(InterfaceC2983f.f8178d);
                i5 = InterfaceC2983f.a.f8179a;
            }
            return new C2981d(i5, enumC2982e, null);
        }
        if (i2 != -1) {
            return i2 != 0 ? i2 != Integer.MAX_VALUE ? (i2 == 1 && enumC2982e == EnumC2982e.DROP_OLDEST) ? new C2988k(null) : new C2981d(i2, enumC2982e, null) : new C2989l(null) : enumC2982e == enumC2982e2 ? new C2996s(null) : new C2981d(1, enumC2982e, null);
        }
        if (enumC2982e == enumC2982e2) {
            return new C2988k(null);
        }
        throw new IllegalArgumentException("CONFLATED capacity cannot be used with non-default onBufferOverflow".toString());
    }

    /* renamed from: a0 */
    public static C2950b<ByteBuffer, Long> m2453a0(RandomAccessFile randomAccessFile, long j2) {
        if (j2 < 32) {
            throw new C2951a(C1499a.m630p("APK too small for APK Signing Block. ZIP Central Directory offset: ", j2));
        }
        ByteBuffer allocate = ByteBuffer.allocate(24);
        ByteOrder byteOrder = ByteOrder.LITTLE_ENDIAN;
        allocate.order(byteOrder);
        randomAccessFile.seek(j2 - allocate.capacity());
        randomAccessFile.readFully(allocate.array(), allocate.arrayOffset(), allocate.capacity());
        if (allocate.getLong(8) != 2334950737559900225L || allocate.getLong(16) != 3617552046287187010L) {
            throw new C2951a("No APK Signing Block before ZIP Central Directory");
        }
        long j3 = allocate.getLong(0);
        if (j3 < allocate.capacity() || j3 > 2147483639) {
            throw new C2951a(C1499a.m630p("APK Signing Block size out of range: ", j3));
        }
        int i2 = (int) (8 + j3);
        long j4 = j2 - i2;
        if (j4 < 0) {
            throw new C2951a(C1499a.m630p("APK Signing Block offset out of range: ", j4));
        }
        ByteBuffer allocate2 = ByteBuffer.allocate(i2);
        allocate2.order(byteOrder);
        randomAccessFile.seek(j4);
        randomAccessFile.readFully(allocate2.array(), allocate2.arrayOffset(), allocate2.capacity());
        long j5 = allocate2.getLong(0);
        if (j5 == j3) {
            return new C2950b<>(allocate2, Long.valueOf(j4));
        }
        throw new C2951a("APK Signing Block sizes in header and footer do not match: " + j5 + " vs " + j3);
    }

    /* renamed from: a1 */
    public static final void m2454a1(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        C1535e.m691d(35, C1535e.f1719d.m694a(), str);
    }

    @NonNull
    /* renamed from: a2 */
    public static C2852c m2455a2(@NonNull Context context) {
        return (C2852c) ComponentCallbacks2C1553c.m738h(context);
    }

    @NotNull
    /* renamed from: b */
    public static final InterfaceC3055e0 m2456b(@NotNull CoroutineContext coroutineContext) {
        if (coroutineContext.get(InterfaceC3053d1.f8393b) == null) {
            coroutineContext = coroutineContext.plus(m2460c(null, 1, null));
        }
        return new C2956e(coroutineContext);
    }

    @NotNull
    /* renamed from: b0 */
    public static final <VB extends ViewBinding> Class<VB> m2457b0(@NotNull Class<?> cls) {
        Intrinsics.checkNotNullParameter(cls, "<this>");
        Type genericSuperclass = cls.getGenericSuperclass();
        if (genericSuperclass instanceof ParameterizedType) {
            Type[] arguments = ((ParameterizedType) genericSuperclass).getActualTypeArguments();
            Intrinsics.checkNotNullExpressionValue(arguments, "arguments");
            int i2 = 0;
            int length = arguments.length;
            while (i2 < length) {
                Type type = arguments[i2];
                i2++;
                Objects.requireNonNull(type, "null cannot be cast to non-null type java.lang.Class<*>");
                Class<VB> cls2 = (Class) type;
                if (ViewBinding.class.isAssignableFrom(cls2)) {
                    return cls2;
                }
            }
        }
        Class<? super Object> superclass = cls.getSuperclass();
        if (superclass != null) {
            return m2457b0(superclass);
        }
        throw new IllegalArgumentException("VB not found");
    }

    @androidx.annotation.Nullable
    /* renamed from: b1 */
    public static Animator m2458b1(@androidx.annotation.Nullable Animator animator, @androidx.annotation.Nullable Animator animator2) {
        if (animator == null) {
            return animator2;
        }
        if (animator2 == null) {
            return animator;
        }
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(animator, animator2);
        return animatorSet;
    }

    @NonNull
    /* renamed from: b2 */
    public static C2852c m2459b2(@NonNull View view) {
        return (C2852c) ComponentCallbacks2C1553c.m739i(view);
    }

    /* renamed from: c */
    public static InterfaceC3102u m2460c(InterfaceC3053d1 interfaceC3053d1, int i2, Object obj) {
        int i3 = i2 & 1;
        return new C3062g1(null);
    }

    /* renamed from: c0 */
    public static C2950b<ByteBuffer, Long> m2461c0(RandomAccessFile randomAccessFile, int i2) {
        int i3;
        if (i2 < 0 || i2 > 65535) {
            throw new IllegalArgumentException(C1499a.m626l("maxCommentSize: ", i2));
        }
        long length = randomAccessFile.length();
        if (length < 22) {
            return null;
        }
        ByteBuffer allocate = ByteBuffer.allocate(((int) Math.min(i2, length - 22)) + 22);
        allocate.order(ByteOrder.LITTLE_ENDIAN);
        long capacity = length - allocate.capacity();
        randomAccessFile.seek(capacity);
        randomAccessFile.readFully(allocate.array(), allocate.arrayOffset(), allocate.capacity());
        m2485j(allocate);
        int capacity2 = allocate.capacity();
        if (capacity2 >= 22) {
            int i4 = capacity2 - 22;
            int min = Math.min(i4, 65535);
            for (int i5 = 0; i5 <= min; i5++) {
                i3 = i4 - i5;
                if (allocate.getInt(i3) == 101010256 && (allocate.getShort(i3 + 20) & UShort.MAX_VALUE) == i5) {
                    break;
                }
            }
        }
        i3 = -1;
        if (i3 == -1) {
            return null;
        }
        allocate.position(i3);
        ByteBuffer slice = allocate.slice();
        slice.order(ByteOrder.LITTLE_ENDIAN);
        return new C2950b<>(slice, Long.valueOf(capacity + i3));
    }

    /* renamed from: c1 */
    public static int m2462c1(int i2, String str) {
        if (i2 >= 0) {
            return i2;
        }
        throw new IllegalArgumentException(C1499a.m637w(str, " may not be negative"));
    }

    @NonNull
    /* renamed from: c2 */
    public static C2852c m2463c2(@NonNull Fragment fragment) {
        return (C2852c) ComponentCallbacks2C1553c.m736e(fragment.getContext()).m1055g(fragment);
    }

    /* renamed from: d */
    public static final void m2464d(AbstractC4408a abstractC4408a, C4409b c4409b, String str) {
        C4410c.b bVar = C4410c.f11628c;
        Logger logger = C4410c.f11627b;
        StringBuilder sb = new StringBuilder();
        sb.append(c4409b.f11625f);
        sb.append(' ');
        StringCompanionObject stringCompanionObject = StringCompanionObject.INSTANCE;
        String format = String.format("%-22s", Arrays.copyOf(new Object[]{str}, 1));
        Intrinsics.checkExpressionValueIsNotNull(format, "java.lang.String.format(format, *args)");
        sb.append(format);
        sb.append(": ");
        sb.append(abstractC4408a.f11618c);
        logger.fine(sb.toString());
    }

    @NotNull
    /* renamed from: d0 */
    public static final <T, R> InterfaceC3006b<R> m2465d0(@NotNull InterfaceC3006b<? extends T> interfaceC3006b, @NotNull Function2<? super T, ? super Continuation<? super InterfaceC3006b<? extends R>>, ? extends Object> function2) {
        int i2 = C3015k.f8263a;
        return new C3014j(new C3013i(interfaceC3006b, function2));
    }

    /* renamed from: d1 */
    public static long m2466d1(long j2, String str) {
        if (j2 >= 0) {
            return j2;
        }
        throw new IllegalArgumentException(C1499a.m637w(str, " may not be negative"));
    }

    @NonNull
    /* renamed from: d2 */
    public static C2852c m2467d2(@NonNull FragmentActivity fragmentActivity) {
        Objects.requireNonNull(fragmentActivity, "You cannot start a load on a not yet attached View or a Fragment where getActivity() returns null (which usually occurs when getActivity() is called before the Fragment is attached or after the Fragment is destroyed).");
        return (C2852c) ComponentCallbacks2C1553c.m735d(fragmentActivity).f1816l.m1056h(fragmentActivity);
    }

    /* renamed from: e */
    public static void m2468e(int i2, String str, int i3) {
        int glCreateShader = GLES20.glCreateShader(i2);
        GLES20.glShaderSource(glCreateShader, str);
        GLES20.glCompileShader(glCreateShader);
        int[] iArr = {0};
        GLES20.glGetShaderiv(glCreateShader, 35713, iArr, 0);
        if (iArr[0] != 1) {
            GLES20.glGetShaderInfoLog(glCreateShader);
        }
        GLES20.glAttachShader(i3, glCreateShader);
        GLES20.glDeleteShader(glCreateShader);
        m2527x();
    }

    /* JADX WARN: Multi-variable type inference failed */
    @NotNull
    /* renamed from: e0 */
    public static final <T> InterfaceC3006b<T> m2469e0(@NotNull InterfaceC3006b<? extends T> interfaceC3006b, @NotNull CoroutineContext coroutineContext) {
        if (coroutineContext.get(InterfaceC3053d1.f8393b) == null) {
            return Intrinsics.areEqual(coroutineContext, EmptyCoroutineContext.INSTANCE) ? interfaceC3006b : interfaceC3006b instanceof InterfaceC3026i ? ((InterfaceC3026i) interfaceC3006b).mo3516b(coroutineContext, -3, EnumC2982e.SUSPEND) : new C3023f(interfaceC3006b, coroutineContext, 0, null, 12);
        }
        throw new IllegalArgumentException(("Flow context cannot contain job in it. Had " + coroutineContext).toString());
    }

    /* renamed from: e1 */
    public static <T> T m2470e1(T t, String str) {
        if (t != null) {
            return t;
        }
        throw new IllegalArgumentException(C1499a.m637w(str, " may not be null"));
    }

    @Nullable
    /* renamed from: e2 */
    public static final <T> Object m2471e2(@NotNull CoroutineContext coroutineContext, @NotNull Function2<? super InterfaceC3055e0, ? super Continuation<? super T>, ? extends Object> function2, @NotNull Continuation<? super T> continuation) {
        boolean z;
        Object m3618a;
        CoroutineContext coroutineContext2 = continuation.get$context();
        CoroutineContext plus = coroutineContext2.plus(coroutineContext);
        InterfaceC3053d1 interfaceC3053d1 = (InterfaceC3053d1) plus.get(InterfaceC3053d1.f8393b);
        if (interfaceC3053d1 != null && !interfaceC3053d1.mo3507b()) {
            throw interfaceC3053d1.mo3553q();
        }
        if (plus == coroutineContext2) {
            C2968q c2968q = new C2968q(plus, continuation);
            m3618a = m2406K1(c2968q, c2968q, function2);
        } else {
            ContinuationInterceptor.Companion companion = ContinuationInterceptor.INSTANCE;
            if (Intrinsics.areEqual((ContinuationInterceptor) plus.get(companion), (ContinuationInterceptor) coroutineContext2.get(companion))) {
                C3113x1 c3113x1 = new C3113x1(plus, continuation);
                Object m3414c = C2952a.m3414c(plus, null);
                try {
                    Object m2406K1 = m2406K1(c3113x1, c3113x1, function2);
                    C2952a.m3412a(plus, m3414c);
                    m3618a = m2406K1;
                } catch (Throwable th) {
                    C2952a.m3412a(plus, m3414c);
                    throw th;
                }
            } else {
                C3073k0 c3073k0 = new C3073k0(plus, continuation);
                c3073k0.m3508i0();
                m2403J1(function2, c3073k0, c3073k0, null, 4);
                while (true) {
                    int i2 = c3073k0._decision;
                    z = false;
                    if (i2 != 0) {
                        if (i2 != 2) {
                            throw new IllegalStateException("Already suspended".toString());
                        }
                    } else if (C3073k0.f8425h.compareAndSet(c3073k0, 0, 1)) {
                        z = true;
                        break;
                    }
                }
                if (z) {
                    m3618a = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
                } else {
                    m3618a = C3071j1.m3618a(c3073k0.m3576L());
                    if (m3618a instanceof C3108w) {
                        throw ((C3108w) m3618a).f8470b;
                    }
                }
            }
        }
        if (m3618a == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
            DebugProbesKt.probeCoroutineSuspended(continuation);
        }
        return m3618a;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @JvmOverloads
    @NotNull
    /* renamed from: f */
    public static final TextView m2472f(@NotNull TextView textView, @NotNull C1325b config, @Nullable Function0<Unit> function0) {
        C1327a c1327a;
        Intrinsics.checkNotNullParameter(textView, "<this>");
        Intrinsics.checkNotNullParameter(config, "config");
        if (TextUtils.isEmpty(textView.getText())) {
            throw new NullPointerException("请优先设置TextView的text");
        }
        SpannableStringBuilder m2413N = m2413N(textView, config.f1079F);
        AttributeSet attributeSet = null;
        int m2528x0 = m2528x0(m2413N, config.f1079F, null, 4);
        int ordinal = config.f1083a.ordinal();
        int i2 = 0;
        if (ordinal == 1) {
            Objects.requireNonNull(config.f1078E, "当type=Type.IMAGE时，必须设置【imageResource】、【imageDrawable】、【imageBitmap】其中一项");
            Drawable drawable = config.f1078E;
            Intrinsics.checkNotNull(drawable);
            c1327a = new C1327a(drawable);
            int i3 = config.f1074A;
            int i4 = config.f1075B;
            c1327a.f1115e = i3;
            c1327a.f1116f = i4;
            WeakReference<Drawable> weakReference = c1327a.f1121k;
            if (weakReference != null) {
                weakReference.clear();
            }
        } else {
            if (ordinal == 3) {
                throw new NullPointerException("当type=Type.URL时,必须设置imageUrl");
            }
            Context context = textView.getContext();
            Intrinsics.checkNotNullExpressionValue(context, "textView.context");
            TagItemView tagItemView = new TagItemView(context, attributeSet, i2, 6);
            tagItemView.setConfig(config);
            Integer num = config.f1094l;
            int intValue = num == null ? config.f1099q : num.intValue();
            Integer num2 = config.f1094l;
            int intValue2 = num2 == null ? config.f1096n : num2.intValue();
            Integer num3 = config.f1094l;
            int intValue3 = num3 == null ? config.f1097o : num3.intValue();
            Integer num4 = config.f1094l;
            tagItemView.setPadding(intValue, intValue2, intValue3, num4 == null ? config.f1098p : num4.intValue());
            if (config.f1101s != null) {
                ShapeableImageView shapeableImageView = new ShapeableImageView(context);
                shapeableImageView.setBackground(config.f1101s);
                ShapeAppearanceModel.Builder builder = ShapeAppearanceModel.builder();
                Float f2 = config.f1088f;
                builder.setTopLeftCornerSize(f2 == null ? config.f1090h : f2.floatValue());
                Float f3 = config.f1088f;
                builder.setTopRightCornerSize(f3 == null ? config.f1092j : f3.floatValue());
                Float f4 = config.f1088f;
                builder.setBottomLeftCornerSize(f4 == null ? config.f1091i : f4.floatValue());
                Float f5 = config.f1088f;
                builder.setBottomRightCornerSize(f5 == null ? config.f1093k : f5.floatValue());
                Unit unit = Unit.INSTANCE;
                shapeableImageView.setShapeAppearanceModel(builder.build());
                FrameLayout frameLayout = new FrameLayout(context);
                int i5 = config.f1086d;
                if (i5 == 0) {
                    i5 = -2;
                }
                int i6 = config.f1087e;
                frameLayout.addView(shapeableImageView, new FrameLayout.LayoutParams(i5, i6 != 0 ? i6 : -2));
                frameLayout.addView(tagItemView);
                ViewGroup.LayoutParams layoutParams = tagItemView.getLayoutParams();
                FrameLayout.LayoutParams layoutParams2 = layoutParams instanceof FrameLayout.LayoutParams ? (FrameLayout.LayoutParams) layoutParams : null;
                if (layoutParams2 != null) {
                    layoutParams2.gravity = 17;
                }
                tagItemView = frameLayout;
            } else {
                float[] fArr = new float[8];
                Float f6 = config.f1088f;
                fArr[0] = f6 == null ? config.f1090h : f6.floatValue();
                Float f7 = config.f1088f;
                fArr[1] = f7 == null ? config.f1090h : f7.floatValue();
                Float f8 = config.f1088f;
                fArr[2] = f8 == null ? config.f1092j : f8.floatValue();
                Float f9 = config.f1088f;
                fArr[3] = f9 == null ? config.f1092j : f9.floatValue();
                Float f10 = config.f1088f;
                fArr[4] = f10 == null ? config.f1093k : f10.floatValue();
                Float f11 = config.f1088f;
                fArr[5] = f11 == null ? config.f1093k : f11.floatValue();
                Float f12 = config.f1088f;
                fArr[6] = f12 == null ? config.f1091i : f12.floatValue();
                Float f13 = config.f1088f;
                fArr[7] = f13 == null ? config.f1091i : f13.floatValue();
                GradientDrawable gradientDrawable = new GradientDrawable();
                gradientDrawable.setCornerRadii(fArr);
                int[] iArr = new int[2];
                Integer num5 = config.f1102t;
                iArr[0] = num5 == null ? config.f1100r : num5.intValue();
                Integer num6 = config.f1103u;
                iArr[1] = num6 == null ? config.f1100r : num6.intValue();
                gradientDrawable.setColors(iArr);
                int i7 = config.f1105w;
                if (i7 > 0) {
                    gradientDrawable.setStroke(i7, config.f1106x);
                }
                gradientDrawable.setOrientation(config.f1104v);
                tagItemView.setBackground(gradientDrawable);
            }
            c1327a = new C1327a(m2407L(tagItemView));
            Intrinsics.checkNotNullParameter(textView.getText().toString(), "<set-?>");
            int i8 = config.f1086d;
            int i9 = config.f1087e;
            c1327a.f1115e = i8;
            c1327a.f1116f = i9;
            WeakReference<Drawable> weakReference2 = c1327a.f1121k;
            if (weakReference2 != null) {
                weakReference2.clear();
            }
        }
        c1327a.f1120j = config.f1076C;
        c1327a.f1119i = (int) textView.getTextSize();
        c1327a.f1114c = config.f1108z;
        c1327a.m335a(config.f1080G, config.f1081H);
        c1327a.m336b(0, 0);
        int i10 = m2528x0 + 1;
        m2413N.setSpan(c1327a, m2528x0, i10, 33);
        m2529x1(textView, m2413N, m2528x0, i10, function0);
        textView.setText(m2413N);
        return textView;
    }

    @NotNull
    /* renamed from: f0 */
    public static final String m2473f0(long j2) {
        String str;
        if (j2 <= -999500000) {
            str = ((j2 - 500000000) / 1000000000) + " s ";
        } else if (j2 <= -999500) {
            str = ((j2 - 500000) / DurationKt.NANOS_IN_MILLIS) + " ms";
        } else if (j2 <= 0) {
            str = ((j2 - CropImageView.DEFAULT_IMAGE_TO_CROP_BOUNDS_ANIM_DURATION) / 1000) + " µs";
        } else if (j2 < 999500) {
            str = ((j2 + CropImageView.DEFAULT_IMAGE_TO_CROP_BOUNDS_ANIM_DURATION) / 1000) + " µs";
        } else if (j2 < 999500000) {
            str = ((j2 + 500000) / DurationKt.NANOS_IN_MILLIS) + " ms";
        } else {
            str = ((j2 + 500000000) / 1000000000) + " s ";
        }
        StringCompanionObject stringCompanionObject = StringCompanionObject.INSTANCE;
        String format = String.format("%6s", Arrays.copyOf(new Object[]{str}, 1));
        Intrinsics.checkExpressionValueIsNotNull(format, "java.lang.String.format(format, *args)");
        return format;
    }

    /* renamed from: f1 */
    public static void m2474f1(Object obj, String str) {
        if (obj == null) {
            throw new IllegalArgumentException(str);
        }
    }

    @Nullable
    /* renamed from: f2 */
    public static final <T, V> Object m2475f2(@NotNull CoroutineContext coroutineContext, V v, @NotNull Object obj, @NotNull Function2<? super V, ? super Continuation<? super T>, ? extends Object> function2, @NotNull Continuation<? super T> continuation) {
        Object m3414c = C2952a.m3414c(coroutineContext, obj);
        try {
            C3033p c3033p = new C3033p(continuation, coroutineContext);
            if (function2 == null) {
                throw new NullPointerException("null cannot be cast to non-null type (R, kotlin.coroutines.Continuation<T>) -> kotlin.Any?");
            }
            Object invoke = ((Function2) TypeIntrinsics.beforeCheckcastToFunctionOfArity(function2, 2)).invoke(v, c3033p);
            C2952a.m3412a(coroutineContext, m3414c);
            if (invoke == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
                DebugProbesKt.probeCoroutineSuspended(continuation);
            }
            return invoke;
        } catch (Throwable th) {
            C2952a.m3412a(coroutineContext, m3414c);
            throw th;
        }
    }

    /* renamed from: g */
    public static final void m2476g(int i2, @NotNull String message, @Nullable Throwable th) {
        int min;
        Intrinsics.checkParameterIsNotNull(message, "message");
        int i3 = i2 != 5 ? 3 : 5;
        if (th != null) {
            StringBuilder m590L = C1499a.m590L(message, "\n");
            m590L.append(Log.getStackTraceString(th));
            message = m590L.toString();
        }
        int i4 = 0;
        int length = message.length();
        while (i4 < length) {
            int indexOf$default = StringsKt__StringsKt.indexOf$default((CharSequence) message, '\n', i4, false, 4, (Object) null);
            if (indexOf$default == -1) {
                indexOf$default = length;
            }
            while (true) {
                min = Math.min(indexOf$default, i4 + 4000);
                String substring = message.substring(i4, min);
                Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
                Log.println(i3, "OkHttp", substring);
                if (min >= indexOf$default) {
                    break;
                } else {
                    i4 = min;
                }
            }
            i4 = min + 1;
        }
    }

    /* renamed from: g0 */
    public static Map<Integer, ByteBuffer> m2477g0(ByteBuffer byteBuffer) {
        if (byteBuffer.order() != ByteOrder.LITTLE_ENDIAN) {
            throw new IllegalArgumentException("ByteBuffer byte order must be little endian");
        }
        int capacity = byteBuffer.capacity() - 24;
        if (capacity < 8) {
            throw new IllegalArgumentException(C1499a.m629o("end < start: ", capacity, " < ", 8));
        }
        int capacity2 = byteBuffer.capacity();
        if (capacity > byteBuffer.capacity()) {
            throw new IllegalArgumentException(C1499a.m629o("end > capacity: ", capacity, " > ", capacity2));
        }
        int limit = byteBuffer.limit();
        int position = byteBuffer.position();
        int i2 = 0;
        try {
            byteBuffer.position(0);
            byteBuffer.limit(capacity);
            byteBuffer.position(8);
            ByteBuffer slice = byteBuffer.slice();
            slice.order(byteBuffer.order());
            byteBuffer.position(0);
            byteBuffer.limit(limit);
            byteBuffer.position(position);
            LinkedHashMap linkedHashMap = new LinkedHashMap();
            while (slice.hasRemaining()) {
                i2++;
                if (slice.remaining() < 8) {
                    throw new C2951a(C1499a.m626l("Insufficient data to read size of APK Signing Block entry #", i2));
                }
                long j2 = slice.getLong();
                if (j2 < 4 || j2 > 2147483647L) {
                    throw new C2951a("APK Signing Block entry #" + i2 + " size out of range: " + j2);
                }
                int i3 = (int) j2;
                int position2 = slice.position() + i3;
                if (i3 > slice.remaining()) {
                    StringBuilder m589K = C1499a.m589K("APK Signing Block entry #", i2, " size out of range: ", i3, ", available: ");
                    m589K.append(slice.remaining());
                    throw new C2951a(m589K.toString());
                }
                Integer valueOf = Integer.valueOf(slice.getInt());
                int i4 = i3 - 4;
                if (i4 < 0) {
                    throw new IllegalArgumentException(C1499a.m626l("size: ", i4));
                }
                int limit2 = slice.limit();
                int position3 = slice.position();
                int i5 = i4 + position3;
                if (i5 < position3 || i5 > limit2) {
                    throw new BufferUnderflowException();
                }
                slice.limit(i5);
                try {
                    ByteBuffer slice2 = slice.slice();
                    slice2.order(slice.order());
                    slice.position(i5);
                    slice.limit(limit2);
                    linkedHashMap.put(valueOf, slice2);
                    slice.position(position2);
                } catch (Throwable th) {
                    slice.limit(limit2);
                    throw th;
                }
            }
            if (linkedHashMap.isEmpty()) {
                throw new C2951a(C1499a.m626l("not have Id-Value Pair in APK Signing Block entry #", i2));
            }
            return linkedHashMap;
        } catch (Throwable th2) {
            byteBuffer.position(0);
            byteBuffer.limit(limit);
            byteBuffer.position(position);
            throw th2;
        }
    }

    /* renamed from: g1 */
    public static void m2478g1(Object obj, String str) {
        if (obj == null) {
            throw new IllegalStateException(C1499a.m637w(str, " is null"));
        }
    }

    /* renamed from: h */
    public static int m2479h(C2517b c2517b, boolean z) {
        int i2 = z ? c2517b.f6801c : c2517b.f6800b;
        int i3 = z ? c2517b.f6800b : c2517b.f6801c;
        byte[][] bArr = c2517b.f6799a;
        int i4 = 0;
        for (int i5 = 0; i5 < i2; i5++) {
            byte b2 = -1;
            int i6 = 0;
            for (int i7 = 0; i7 < i3; i7++) {
                byte b3 = z ? bArr[i5][i7] : bArr[i7][i5];
                if (b3 == b2) {
                    i6++;
                } else {
                    if (i6 >= 5) {
                        i4 += (i6 - 5) + 3;
                    }
                    b2 = b3;
                    i6 = 1;
                }
            }
            if (i6 >= 5) {
                i4 = (i6 - 5) + 3 + i4;
            }
        }
        return i4;
    }

    /* renamed from: h0 */
    public static ByteBuffer m2480h0(File file) {
        RandomAccessFile randomAccessFile = null;
        C2950b<ByteBuffer, Long> m2461c0 = null;
        if (!file.exists() || !file.isFile()) {
            return null;
        }
        try {
            RandomAccessFile randomAccessFile2 = new RandomAccessFile(file, "r");
            try {
                boolean z = false;
                if (randomAccessFile2.length() >= 22 && (m2461c0 = m2461c0(randomAccessFile2, 0)) == null) {
                    m2461c0 = m2461c0(randomAccessFile2, 65535);
                }
                if (m2461c0 == null) {
                    throw new C2951a("Not an APK file: ZIP End of Central Directory record not found");
                }
                ByteBuffer byteBuffer = m2461c0.f8084a;
                long longValue = m2461c0.f8085b.longValue();
                long j2 = longValue - 20;
                if (j2 >= 0) {
                    randomAccessFile2.seek(j2);
                    if (randomAccessFile2.readInt() == 1347094023) {
                        z = true;
                    }
                }
                if (z) {
                    throw new C2951a("ZIP64 APK not supported");
                }
                ByteBuffer byteBuffer2 = m2453a0(randomAccessFile2, m2486j0(byteBuffer, longValue)).f8084a;
                randomAccessFile2.close();
                return byteBuffer2;
            } catch (Throwable th) {
                th = th;
                randomAccessFile = randomAccessFile2;
                if (randomAccessFile != null) {
                    randomAccessFile.close();
                }
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }

    /* renamed from: h1 */
    public static void m2481h1(Throwable th) {
        if (th == null) {
            int i2 = C4345a.f11199a;
            th = new NullPointerException(C1499a.m637w("onError called with a null Throwable.", " Null values are generally not allowed in 3.x operators and sources."));
        } else {
            boolean z = true;
            if (!(th instanceof C4338b) && !(th instanceof IllegalStateException) && !(th instanceof NullPointerException) && !(th instanceof IllegalArgumentException) && !(th instanceof C4337a)) {
                z = false;
            }
            if (!z) {
                th = new C4340d(th);
            }
        }
        th.printStackTrace();
        Thread currentThread = Thread.currentThread();
        currentThread.getUncaughtExceptionHandler().uncaughtException(currentThread, th);
    }

    /* renamed from: i */
    public static final boolean m2482i(@NotNull byte[] a2, int i2, @NotNull byte[] b2, int i3, int i4) {
        Intrinsics.checkNotNullParameter(a2, "a");
        Intrinsics.checkNotNullParameter(b2, "b");
        for (int i5 = 0; i5 < i4; i5++) {
            if (a2[i5 + i2] != b2[i5 + i3]) {
                return false;
            }
        }
        return true;
    }

    @androidx.annotation.Nullable
    /* renamed from: i0 */
    public static String m2483i0(XmlPullParser xmlPullParser, String str) {
        int attributeCount = xmlPullParser.getAttributeCount();
        for (int i2 = 0; i2 < attributeCount; i2++) {
            if (xmlPullParser.getAttributeName(i2).equals(str)) {
                return xmlPullParser.getAttributeValue(i2);
            }
        }
        return null;
    }

    /* renamed from: i1 */
    public static void m2484i1(@NotNull InterfaceC2846i interfaceC2846i, boolean z, int i2, @NotNull Function1<? super View, Unit> block) {
        Intrinsics.checkNotNullParameter(interfaceC2846i, "this");
        Intrinsics.checkNotNullParameter(block, "block");
        ViewBinding failedBinding = interfaceC2846i.getFailedBinding();
        if (failedBinding == null) {
            return;
        }
        View root = failedBinding.getRoot();
        Intrinsics.checkNotNullExpressionValue(root, "viewBinding.root");
        View findViewById = root.findViewById(i2);
        if (z) {
            block.invoke(findViewById);
        }
        m2377B(findViewById, 0L, new d(block), 1);
    }

    /* renamed from: j */
    public static void m2485j(ByteBuffer byteBuffer) {
        if (byteBuffer.order() != ByteOrder.LITTLE_ENDIAN) {
            throw new IllegalArgumentException("ByteBuffer byte order must be little endian");
        }
    }

    /* renamed from: j0 */
    public static long m2486j0(ByteBuffer byteBuffer, long j2) {
        m2485j(byteBuffer);
        long j3 = byteBuffer.getInt(byteBuffer.position() + 16) & 4294967295L;
        if (j3 <= j2) {
            m2485j(byteBuffer);
            if ((4294967295L & byteBuffer.getInt(byteBuffer.position() + 12)) + j3 == j2) {
                return j3;
            }
            throw new C2951a("ZIP Central Directory is not immediately followed by End of Central Directory");
        }
        throw new C2951a("ZIP Central Directory offset out of range: " + j3 + ". ZIP End of Central Directory offset: " + j2);
    }

    /* renamed from: j1 */
    public static C2675c m2487j1(String str, InputStream inputStream) {
        C2673a c2673a = new C2673a();
        new C2680h(str, inputStream, null, null, c2673a);
        return c2673a.f7270c;
    }

    /* renamed from: k */
    public static void m2488k(String str) {
        if (C2344d0.f6035a >= 18) {
            Trace.beginSection(str);
        }
    }

    @NotNull
    /* renamed from: k0 */
    public static final String m2489k0(@NotNull Object obj) {
        return obj.getClass().getSimpleName();
    }

    @NonNull
    /* renamed from: k1 */
    public static C2648g m2490k1(@NonNull Context context, int i2) {
        C2648g c2648g = new C2648g();
        XmlResourceParser openXmlResourceParser = context.getAssets().openXmlResourceParser(i2, "AndroidManifest.xml");
        do {
            try {
                if (openXmlResourceParser.getEventType() == 2) {
                    String name = openXmlResourceParser.getName();
                    if (TextUtils.equals("manifest", name)) {
                        c2648g.f7238a = openXmlResourceParser.getAttributeValue(null, "package");
                    }
                    if (TextUtils.equals("uses-sdk", name)) {
                        C2648g.e eVar = new C2648g.e();
                        eVar.f7252a = openXmlResourceParser.getAttributeIntValue("http://schemas.android.com/apk/res/android", "minSdkVersion", 0);
                        c2648g.f7239b = eVar;
                    }
                    if (TextUtils.equals("uses-permission", name) || TextUtils.equals("uses-permission-sdk-23", name) || TextUtils.equals("uses-permission-sdk-m", name)) {
                        List<C2648g.c> list = c2648g.f7240c;
                        C2648g.c cVar = new C2648g.c();
                        cVar.f7247b = openXmlResourceParser.getAttributeValue("http://schemas.android.com/apk/res/android", "name");
                        cVar.f7248c = openXmlResourceParser.getAttributeIntValue("http://schemas.android.com/apk/res/android", "maxSdkVersion", Integer.MAX_VALUE);
                        cVar.f7249d = openXmlResourceParser.getAttributeIntValue("http://schemas.android.com/apk/res/android", "usesPermissionFlags", 0);
                        list.add(cVar);
                    }
                    if (TextUtils.equals("application", name)) {
                        C2648g.b bVar = new C2648g.b();
                        openXmlResourceParser.getAttributeValue("http://schemas.android.com/apk/res/android", "name");
                        bVar.f7245a = openXmlResourceParser.getAttributeBooleanValue("http://schemas.android.com/apk/res/android", "requestLegacyExternalStorage", false);
                        c2648g.f7241d = bVar;
                    }
                    if (TextUtils.equals(ActivityChooserModel.ATTRIBUTE_ACTIVITY, name) || TextUtils.equals("activity-alias", name)) {
                        List<C2648g.a> list2 = c2648g.f7242e;
                        C2648g.a aVar = new C2648g.a();
                        openXmlResourceParser.getAttributeValue("http://schemas.android.com/apk/res/android", "name");
                        aVar.f7244a = openXmlResourceParser.getAttributeBooleanValue("http://schemas.android.com/apk/res/android", "supportsPictureInPicture", false);
                        list2.add(aVar);
                    }
                    if (TextUtils.equals(NotificationCompat.CATEGORY_SERVICE, name)) {
                        List<C2648g.d> list3 = c2648g.f7243f;
                        C2648g.d dVar = new C2648g.d();
                        dVar.f7250a = openXmlResourceParser.getAttributeValue("http://schemas.android.com/apk/res/android", "name");
                        dVar.f7251b = openXmlResourceParser.getAttributeValue("http://schemas.android.com/apk/res/android", "permission");
                        list3.add(dVar);
                    }
                }
            } catch (Throwable th) {
                if (openXmlResourceParser != null) {
                    try {
                        openXmlResourceParser.close();
                    } catch (Throwable th2) {
                        th.addSuppressed(th2);
                    }
                }
                throw th;
            }
        } while (openXmlResourceParser.next() != 1);
        openXmlResourceParser.close();
        return c2648g;
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x005c  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0069  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x006e  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0073  */
    /* renamed from: l */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.graphics.Bitmap m2491l(android.content.Context r6, android.graphics.Bitmap r7, int r8) {
        /*
            r0 = 23
            r1 = 0
            android.renderscript.RenderScript r6 = android.renderscript.RenderScript.create(r6)     // Catch: java.lang.Throwable -> L56
            android.renderscript.RenderScript$RSMessageHandler r2 = new android.renderscript.RenderScript$RSMessageHandler     // Catch: java.lang.Throwable -> L50
            r2.<init>()     // Catch: java.lang.Throwable -> L50
            r6.setMessageHandler(r2)     // Catch: java.lang.Throwable -> L50
            android.renderscript.Allocation$MipmapControl r2 = android.renderscript.Allocation.MipmapControl.MIPMAP_NONE     // Catch: java.lang.Throwable -> L50
            r3 = 1
            android.renderscript.Allocation r2 = android.renderscript.Allocation.createFromBitmap(r6, r7, r2, r3)     // Catch: java.lang.Throwable -> L50
            android.renderscript.Type r3 = r2.getType()     // Catch: java.lang.Throwable -> L4d
            android.renderscript.Allocation r3 = android.renderscript.Allocation.createTyped(r6, r3)     // Catch: java.lang.Throwable -> L4d
            android.renderscript.Element r4 = android.renderscript.Element.U8_4(r6)     // Catch: java.lang.Throwable -> L48
            android.renderscript.ScriptIntrinsicBlur r1 = android.renderscript.ScriptIntrinsicBlur.create(r6, r4)     // Catch: java.lang.Throwable -> L48
            r1.setInput(r2)     // Catch: java.lang.Throwable -> L48
            float r8 = (float) r8     // Catch: java.lang.Throwable -> L48
            r1.setRadius(r8)     // Catch: java.lang.Throwable -> L48
            r1.forEach(r3)     // Catch: java.lang.Throwable -> L48
            r3.copyTo(r7)     // Catch: java.lang.Throwable -> L48
            int r8 = android.os.Build.VERSION.SDK_INT
            if (r8 < r0) goto L3b
            android.renderscript.RenderScript.releaseAllContexts()
            goto L3e
        L3b:
            r6.destroy()
        L3e:
            r2.destroy()
            r3.destroy()
            r1.destroy()
            return r7
        L48:
            r7 = move-exception
            r5 = r1
            r1 = r6
            r6 = r5
            goto L5a
        L4d:
            r7 = move-exception
            r3 = r1
            goto L53
        L50:
            r7 = move-exception
            r2 = r1
            r3 = r2
        L53:
            r1 = r6
            r6 = r3
            goto L5a
        L56:
            r7 = move-exception
            r6 = r1
            r2 = r6
            r3 = r2
        L5a:
            if (r1 == 0) goto L67
            int r8 = android.os.Build.VERSION.SDK_INT
            if (r8 < r0) goto L64
            android.renderscript.RenderScript.releaseAllContexts()
            goto L67
        L64:
            r1.destroy()
        L67:
            if (r2 == 0) goto L6c
            r2.destroy()
        L6c:
            if (r3 == 0) goto L71
            r3.destroy()
        L71:
            if (r6 == 0) goto L76
            r6.destroy()
        L76:
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p250p1.C2354n.m2491l(android.content.Context, android.graphics.Bitmap, int):android.graphics.Bitmap");
    }

    /* renamed from: l0 */
    public static File m2492l0() {
        StringBuilder sb = new StringBuilder();
        sb.append(Environment.getExternalStorageDirectory().getPath());
        File file = new File(C1499a.m582D(sb, File.separator, "AWSP"));
        if (!file.exists()) {
            file.mkdirs();
        }
        return file;
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x01a5  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x01bc A[SYNTHETIC] */
    @androidx.annotation.Nullable
    /* renamed from: l1 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.ArrayList<p005b.p199l.p200a.p201a.p251q1.p252s.C2390d.a> m2493l1(p005b.p199l.p200a.p201a.p250p1.C2360t r27) {
        /*
            Method dump skipped, instructions count: 448
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p250p1.C2354n.m2493l1(b.l.a.a.p1.t):java.util.ArrayList");
    }

    /* renamed from: m */
    public static Bitmap m2494m(Bitmap bitmap, int i2, boolean z) {
        int[] iArr;
        int i3 = i2;
        Bitmap copy = z ? bitmap : bitmap.copy(bitmap.getConfig(), true);
        if (i3 < 1) {
            return null;
        }
        int width = copy.getWidth();
        int height = copy.getHeight();
        int i4 = width * height;
        int[] iArr2 = new int[i4];
        copy.getPixels(iArr2, 0, width, 0, 0, width, height);
        int i5 = width - 1;
        int i6 = height - 1;
        int i7 = i3 + i3 + 1;
        int[] iArr3 = new int[i4];
        int[] iArr4 = new int[i4];
        int[] iArr5 = new int[i4];
        int[] iArr6 = new int[Math.max(width, height)];
        int i8 = (i7 + 1) >> 1;
        int i9 = i8 * i8;
        int i10 = i9 * 256;
        int[] iArr7 = new int[i10];
        for (int i11 = 0; i11 < i10; i11++) {
            iArr7[i11] = i11 / i9;
        }
        int[][] iArr8 = (int[][]) Array.newInstance((Class<?>) int.class, i7, 3);
        int i12 = i3 + 1;
        int i13 = 0;
        int i14 = 0;
        int i15 = 0;
        while (i13 < height) {
            Bitmap bitmap2 = copy;
            int i16 = height;
            int i17 = 0;
            int i18 = 0;
            int i19 = 0;
            int i20 = 0;
            int i21 = 0;
            int i22 = 0;
            int i23 = 0;
            int i24 = 0;
            int i25 = -i3;
            int i26 = 0;
            while (i25 <= i3) {
                int i27 = i6;
                int[] iArr9 = iArr6;
                int i28 = iArr2[Math.min(i5, Math.max(i25, 0)) + i14];
                int[] iArr10 = iArr8[i25 + i3];
                iArr10[0] = (i28 & ItemTouchHelper.ACTION_MODE_DRAG_MASK) >> 16;
                iArr10[1] = (i28 & 65280) >> 8;
                iArr10[2] = i28 & 255;
                int abs = i12 - Math.abs(i25);
                i26 = (iArr10[0] * abs) + i26;
                i17 = (iArr10[1] * abs) + i17;
                i18 = (iArr10[2] * abs) + i18;
                if (i25 > 0) {
                    i22 += iArr10[0];
                    i23 += iArr10[1];
                    i24 += iArr10[2];
                } else {
                    i19 += iArr10[0];
                    i20 += iArr10[1];
                    i21 += iArr10[2];
                }
                i25++;
                i6 = i27;
                iArr6 = iArr9;
            }
            int i29 = i6;
            int[] iArr11 = iArr6;
            int i30 = i3;
            int i31 = i26;
            int i32 = 0;
            while (i32 < width) {
                iArr3[i14] = iArr7[i31];
                iArr4[i14] = iArr7[i17];
                iArr5[i14] = iArr7[i18];
                int i33 = i31 - i19;
                int i34 = i17 - i20;
                int i35 = i18 - i21;
                int[] iArr12 = iArr8[((i30 - i3) + i7) % i7];
                int i36 = i19 - iArr12[0];
                int i37 = i20 - iArr12[1];
                int i38 = i21 - iArr12[2];
                if (i13 == 0) {
                    iArr = iArr7;
                    iArr11[i32] = Math.min(i32 + i3 + 1, i5);
                } else {
                    iArr = iArr7;
                }
                int i39 = iArr2[i15 + iArr11[i32]];
                iArr12[0] = (i39 & ItemTouchHelper.ACTION_MODE_DRAG_MASK) >> 16;
                iArr12[1] = (i39 & 65280) >> 8;
                iArr12[2] = i39 & 255;
                int i40 = i22 + iArr12[0];
                int i41 = i23 + iArr12[1];
                int i42 = i24 + iArr12[2];
                i31 = i33 + i40;
                i17 = i34 + i41;
                i18 = i35 + i42;
                i30 = (i30 + 1) % i7;
                int[] iArr13 = iArr8[i30 % i7];
                i19 = i36 + iArr13[0];
                i20 = i37 + iArr13[1];
                i21 = i38 + iArr13[2];
                i22 = i40 - iArr13[0];
                i23 = i41 - iArr13[1];
                i24 = i42 - iArr13[2];
                i14++;
                i32++;
                iArr7 = iArr;
            }
            i15 += width;
            i13++;
            copy = bitmap2;
            height = i16;
            i6 = i29;
            iArr6 = iArr11;
        }
        Bitmap bitmap3 = copy;
        int i43 = i6;
        int[] iArr14 = iArr6;
        int i44 = height;
        int[] iArr15 = iArr7;
        int i45 = 0;
        while (i45 < width) {
            int i46 = -i3;
            int i47 = i7;
            int[] iArr16 = iArr2;
            int i48 = 0;
            int i49 = 0;
            int i50 = 0;
            int i51 = 0;
            int i52 = 0;
            int i53 = 0;
            int i54 = 0;
            int i55 = i46;
            int i56 = i46 * width;
            int i57 = 0;
            int i58 = 0;
            while (i55 <= i3) {
                int i59 = width;
                int max = Math.max(0, i56) + i45;
                int[] iArr17 = iArr8[i55 + i3];
                iArr17[0] = iArr3[max];
                iArr17[1] = iArr4[max];
                iArr17[2] = iArr5[max];
                int abs2 = i12 - Math.abs(i55);
                i57 = (iArr3[max] * abs2) + i57;
                i58 = (iArr4[max] * abs2) + i58;
                i48 = (iArr5[max] * abs2) + i48;
                if (i55 > 0) {
                    i52 += iArr17[0];
                    i53 += iArr17[1];
                    i54 += iArr17[2];
                } else {
                    i49 += iArr17[0];
                    i50 += iArr17[1];
                    i51 += iArr17[2];
                }
                int i60 = i43;
                if (i55 < i60) {
                    i56 += i59;
                }
                i55++;
                i43 = i60;
                width = i59;
            }
            int i61 = width;
            int i62 = i43;
            int i63 = i3;
            int i64 = i45;
            int i65 = i58;
            int i66 = i44;
            int i67 = i57;
            int i68 = 0;
            while (i68 < i66) {
                iArr16[i64] = (iArr16[i64] & ViewCompat.MEASURED_STATE_MASK) | (iArr15[i67] << 16) | (iArr15[i65] << 8) | iArr15[i48];
                int i69 = i67 - i49;
                int i70 = i65 - i50;
                int i71 = i48 - i51;
                int[] iArr18 = iArr8[((i63 - i3) + i47) % i47];
                int i72 = i49 - iArr18[0];
                int i73 = i50 - iArr18[1];
                int i74 = i51 - iArr18[2];
                if (i45 == 0) {
                    iArr14[i68] = Math.min(i68 + i12, i62) * i61;
                }
                int i75 = iArr14[i68] + i45;
                iArr18[0] = iArr3[i75];
                iArr18[1] = iArr4[i75];
                iArr18[2] = iArr5[i75];
                int i76 = i52 + iArr18[0];
                int i77 = i53 + iArr18[1];
                int i78 = i54 + iArr18[2];
                i67 = i69 + i76;
                i65 = i70 + i77;
                i48 = i71 + i78;
                i63 = (i63 + 1) % i47;
                int[] iArr19 = iArr8[i63];
                i49 = i72 + iArr19[0];
                i50 = i73 + iArr19[1];
                i51 = i74 + iArr19[2];
                i52 = i76 - iArr19[0];
                i53 = i77 - iArr19[1];
                i54 = i78 - iArr19[2];
                i64 += i61;
                i68++;
                i3 = i2;
            }
            i45++;
            i3 = i2;
            i43 = i62;
            i44 = i66;
            i7 = i47;
            iArr2 = iArr16;
            width = i61;
        }
        int i79 = width;
        bitmap3.setPixels(iArr2, 0, i79, 0, 0, i79, i44);
        return bitmap3;
    }

    @NotNull
    /* renamed from: m0 */
    public static final String m2495m0(@NotNull Object obj) {
        return Integer.toHexString(System.identityHashCode(obj));
    }

    @NotNull
    /* renamed from: m1 */
    public static final Object m2496m1(Object obj, E e2) {
        if (obj == null) {
            return e2;
        }
        if (obj instanceof ArrayList) {
            ((ArrayList) obj).add(e2);
            return obj;
        }
        ArrayList arrayList = new ArrayList(4);
        arrayList.add(obj);
        arrayList.add(e2);
        return arrayList;
    }

    @NotNull
    /* renamed from: n */
    public static final InterfaceC4745g m2497n(@NotNull InterfaceC4762x buffer) {
        Intrinsics.checkNotNullParameter(buffer, "$this$buffer");
        return new C4757s(buffer);
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x0029, code lost:
    
        if (r2 == null) goto L26;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x002b, code lost:
    
        r0 = r2._state;
        r5 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x0030, code lost:
    
        if ((r0 instanceof p379c.p380a.C3105v) == false) goto L21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x0036, code lost:
    
        if (((p379c.p380a.C3105v) r0).f8465d == null) goto L21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x0038, code lost:
    
        r2.m3609p();
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x0043, code lost:
    
        if (r5 == false) goto L24;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x0045, code lost:
    
        r3 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x0046, code lost:
    
        if (r3 == null) goto L26;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x0048, code lost:
    
        return r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x003c, code lost:
    
        r2._decision = 0;
        r2._state = p379c.p380a.C3035c.f8343c;
        r5 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x004e, code lost:
    
        return new p379c.p380a.C3069j<>(r6, 2);
     */
    @org.jetbrains.annotations.NotNull
    /* renamed from: n0 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final <T> p379c.p380a.C3069j<T> m2498n0(@org.jetbrains.annotations.NotNull kotlin.coroutines.Continuation<? super T> r6) {
        /*
            boolean r0 = r6 instanceof p379c.p380a.p381a.C2957f
            r1 = 2
            if (r0 != 0) goto Lb
            c.a.j r0 = new c.a.j
            r0.<init>(r6, r1)
            return r0
        Lb:
            r0 = r6
            c.a.a.f r0 = (p379c.p380a.p381a.C2957f) r0
        Le:
            java.lang.Object r2 = r0._reusableCancellableContinuation
            r3 = 0
            if (r2 != 0) goto L19
            c.a.a.s r2 = p379c.p380a.p381a.C2958g.f8109b
            r0._reusableCancellableContinuation = r2
            r2 = r3
            goto L29
        L19:
            boolean r4 = r2 instanceof p379c.p380a.C3069j
            if (r4 == 0) goto L4f
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r4 = p379c.p380a.p381a.C2957f.f8102g
            c.a.a.s r5 = p379c.p380a.p381a.C2958g.f8109b
            boolean r4 = r4.compareAndSet(r0, r2, r5)
            if (r4 == 0) goto Le
            c.a.j r2 = (p379c.p380a.C3069j) r2
        L29:
            if (r2 == 0) goto L49
            java.lang.Object r0 = r2._state
            boolean r4 = r0 instanceof p379c.p380a.C3105v
            r5 = 0
            if (r4 == 0) goto L3c
            c.a.v r0 = (p379c.p380a.C3105v) r0
            java.lang.Object r0 = r0.f8465d
            if (r0 == 0) goto L3c
            r2.m3609p()
            goto L43
        L3c:
            r2._decision = r5
            c.a.c r0 = p379c.p380a.C3035c.f8343c
            r2._state = r0
            r5 = 1
        L43:
            if (r5 == 0) goto L46
            r3 = r2
        L46:
            if (r3 == 0) goto L49
            return r3
        L49:
            c.a.j r0 = new c.a.j
            r0.<init>(r6, r1)
            return r0
        L4f:
            java.lang.String r6 = "Inconsistent state "
            java.lang.String r6 = p005b.p131d.p132a.p133a.C1499a.m636v(r6, r2)
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r6 = r6.toString()
            r0.<init>(r6)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p250p1.C2354n.m2498n0(kotlin.coroutines.Continuation):c.a.j");
    }

    /* renamed from: n1 */
    public static int m2499n1(int i2, String str) {
        if (i2 > 0) {
            return i2;
        }
        throw new IllegalArgumentException(C1499a.m637w(str, " may not be negative or zero"));
    }

    @NotNull
    /* renamed from: o */
    public static final InterfaceC4746h m2500o(@NotNull InterfaceC4764z buffer) {
        Intrinsics.checkNotNullParameter(buffer, "$this$buffer");
        return new C4758t(buffer);
    }

    /* renamed from: o0 */
    public static int m2501o0(int[] iArr, int i2, boolean z) {
        int[] iArr2 = iArr;
        int i3 = 0;
        for (int i4 : iArr2) {
            i3 += i4;
        }
        int length = iArr2.length;
        int i5 = 0;
        int i6 = 0;
        int i7 = 0;
        while (true) {
            int i8 = length - 1;
            if (i5 >= i8) {
                return i6;
            }
            int i9 = 1 << i5;
            i7 |= i9;
            int i10 = 1;
            while (i10 < iArr2[i5]) {
                int i11 = i3 - i10;
                int i12 = length - i5;
                int i13 = i12 - 2;
                int m2386E = m2386E(i11 - 1, i13);
                if (z && i7 == 0) {
                    int i14 = i12 - 1;
                    if (i11 - i14 >= i14) {
                        m2386E -= m2386E(i11 - i12, i13);
                    }
                }
                if (i12 - 1 > 1) {
                    int i15 = 0;
                    for (int i16 = i11 - i13; i16 > i2; i16--) {
                        i15 += m2386E((i11 - i16) - 1, i12 - 3);
                    }
                    m2386E -= (i8 - i5) * i15;
                } else if (i11 > i2) {
                    m2386E--;
                }
                i6 += m2386E;
                i10++;
                i7 &= ~i9;
                iArr2 = iArr;
            }
            i3 -= i10;
            i5++;
            iArr2 = iArr;
        }
    }

    /* renamed from: o1 */
    public static String m2502o1(File file) {
        boolean z;
        RandomAccessFile randomAccessFile = null;
        try {
            RandomAccessFile randomAccessFile2 = new RandomAccessFile(file, "r");
            try {
                long length = randomAccessFile2.length();
                byte[] bArr = C2949a.f8083a;
                int length2 = bArr.length;
                byte[] bArr2 = new byte[length2];
                long length3 = length - bArr.length;
                randomAccessFile2.seek(length3);
                randomAccessFile2.readFully(bArr2);
                if (length2 == bArr.length) {
                    int i2 = 0;
                    while (true) {
                        byte[] bArr3 = C2949a.f8083a;
                        if (i2 >= bArr3.length) {
                            z = true;
                            break;
                        }
                        if (bArr2[i2] != bArr3[i2]) {
                            break;
                        }
                        i2++;
                    }
                }
                z = false;
                if (!z) {
                    throw new Exception("zip v1 magic not found");
                }
                long j2 = length3 - 2;
                randomAccessFile2.seek(j2);
                byte[] bArr4 = new byte[2];
                randomAccessFile2.readFully(bArr4);
                int i3 = ByteBuffer.wrap(bArr4).order(ByteOrder.LITTLE_ENDIAN).getShort(0);
                if (i3 <= 0) {
                    throw new Exception("zip channel info not found");
                }
                randomAccessFile2.seek(j2 - i3);
                byte[] bArr5 = new byte[i3];
                randomAccessFile2.readFully(bArr5);
                String trim = new String(bArr5, "UTF-8").trim();
                randomAccessFile2.close();
                return trim;
            } catch (Throwable th) {
                th = th;
                randomAccessFile = randomAccessFile2;
                if (randomAccessFile != null) {
                    randomAccessFile.close();
                }
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Nullable
    /* renamed from: p */
    public static final <E> C2975x m2503p(@NotNull Function1<? super E, Unit> function1, E e2, @Nullable C2975x c2975x) {
        try {
            function1.invoke(e2);
        } catch (Throwable th) {
            if (c2975x == null || c2975x.getCause() == th) {
                return new C2975x(C1499a.m636v("Exception in undelivered element handler for ", e2), th);
            }
            ExceptionsKt__ExceptionsKt.addSuppressed(c2975x, th);
        }
        return c2975x;
    }

    /* renamed from: p0 */
    public static String m2504p0(Throwable th) {
        for (Throwable th2 = th; th2 != null; th2 = th2.getCause()) {
            if (th2 instanceof UnknownHostException) {
                return "";
            }
        }
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        th.printStackTrace(printWriter);
        printWriter.flush();
        return stringWriter.toString();
    }

    @NotNull
    /* renamed from: p1 */
    public static final <T> Object m2505p1(@Nullable Object obj, @NotNull Continuation<? super T> continuation) {
        if (obj instanceof C3108w) {
            Result.Companion companion = Result.INSTANCE;
            return Result.m6055constructorimpl(ResultKt.createFailure(((C3108w) obj).f8470b));
        }
        Result.Companion companion2 = Result.INSTANCE;
        return Result.m6055constructorimpl(obj);
    }

    /* renamed from: q */
    public static /* synthetic */ C2975x m2506q(Function1 function1, Object obj, C2975x c2975x, int i2) {
        int i3 = i2 & 2;
        return m2503p(function1, obj, null);
    }

    /* renamed from: q0 */
    public static DateFormat m2507q0(int i2, int i3) {
        String str;
        String str2;
        StringBuilder sb = new StringBuilder();
        if (i2 == 0) {
            str = "EEEE, MMMM d, yyyy";
        } else if (i2 == 1) {
            str = "MMMM d, yyyy";
        } else if (i2 == 2) {
            str = "MMM d, yyyy";
        } else {
            if (i2 != 3) {
                throw new IllegalArgumentException(C1499a.m626l("Unknown DateFormat style: ", i2));
            }
            str = "M/d/yy";
        }
        sb.append(str);
        sb.append(" ");
        if (i3 == 0 || i3 == 1) {
            str2 = "h:mm:ss a z";
        } else if (i3 == 2) {
            str2 = "h:mm:ss a";
        } else {
            if (i3 != 3) {
                throw new IllegalArgumentException(C1499a.m626l("Unknown DateFormat style: ", i3));
            }
            str2 = "h:mm a";
        }
        sb.append(str2);
        return new SimpleDateFormat(sb.toString(), Locale.US);
    }

    /* renamed from: q1 */
    public static String m2508q1(StringBuilder sb, int i2, int i3) {
        int i4;
        int i5;
        if (i2 >= i3) {
            return sb.toString();
        }
        if (sb.charAt(i2) == '/') {
            i2++;
        }
        int i6 = i2;
        int i7 = i6;
        while (i6 <= i3) {
            if (i6 == i3) {
                i4 = i6;
            } else if (sb.charAt(i6) == '/') {
                i4 = i6 + 1;
            } else {
                i6++;
            }
            int i8 = i7 + 1;
            if (i6 == i8 && sb.charAt(i7) == '.') {
                sb.delete(i7, i4);
                i3 -= i4 - i7;
            } else {
                if (i6 == i7 + 2 && sb.charAt(i7) == '.' && sb.charAt(i8) == '.') {
                    i5 = sb.lastIndexOf("/", i7 - 2) + 1;
                    int i9 = i5 > i2 ? i5 : i2;
                    sb.delete(i9, i4);
                    i3 -= i4 - i9;
                } else {
                    i5 = i6 + 1;
                }
                i7 = i5;
            }
            i6 = i7;
        }
        return sb.toString();
    }

    /* renamed from: r */
    public static void m2509r(CoroutineContext coroutineContext, CancellationException cancellationException, int i2, Object obj) {
        int i3 = i2 & 1;
        InterfaceC3053d1 interfaceC3053d1 = (InterfaceC3053d1) coroutineContext.get(InterfaceC3053d1.f8393b);
        if (interfaceC3053d1 != null) {
            interfaceC3053d1.mo3551d(null);
        }
    }

    /* renamed from: r0 */
    public static int[] m2510r0(String str) {
        int i2;
        int[] iArr = new int[4];
        if (TextUtils.isEmpty(str)) {
            iArr[0] = -1;
            return iArr;
        }
        int length = str.length();
        int indexOf = str.indexOf(35);
        if (indexOf != -1) {
            length = indexOf;
        }
        int indexOf2 = str.indexOf(63);
        if (indexOf2 == -1 || indexOf2 > length) {
            indexOf2 = length;
        }
        int indexOf3 = str.indexOf(47);
        if (indexOf3 == -1 || indexOf3 > indexOf2) {
            indexOf3 = indexOf2;
        }
        int indexOf4 = str.indexOf(58);
        if (indexOf4 > indexOf3) {
            indexOf4 = -1;
        }
        int i3 = indexOf4 + 2;
        if (i3 < indexOf2 && str.charAt(indexOf4 + 1) == '/' && str.charAt(i3) == '/') {
            i2 = str.indexOf(47, indexOf4 + 3);
            if (i2 == -1 || i2 > indexOf2) {
                i2 = indexOf2;
            }
        } else {
            i2 = indexOf4 + 1;
        }
        iArr[0] = indexOf4;
        iArr[1] = i2;
        iArr[2] = indexOf2;
        iArr[3] = length;
        return iArr;
    }

    /* renamed from: r1 */
    public static String m2511r1(@androidx.annotation.Nullable String str, @androidx.annotation.Nullable String str2) {
        StringBuilder sb = new StringBuilder();
        if (str == null) {
            str = "";
        }
        if (str2 == null) {
            str2 = "";
        }
        int[] m2510r0 = m2510r0(str2);
        if (m2510r0[0] != -1) {
            sb.append(str2);
            m2508q1(sb, m2510r0[1], m2510r0[2]);
            return sb.toString();
        }
        int[] m2510r02 = m2510r0(str);
        if (m2510r0[3] == 0) {
            sb.append((CharSequence) str, 0, m2510r02[3]);
            sb.append(str2);
            return sb.toString();
        }
        if (m2510r0[2] == 0) {
            sb.append((CharSequence) str, 0, m2510r02[2]);
            sb.append(str2);
            return sb.toString();
        }
        if (m2510r0[1] != 0) {
            int i2 = m2510r02[0] + 1;
            sb.append((CharSequence) str, 0, i2);
            sb.append(str2);
            return m2508q1(sb, m2510r0[1] + i2, i2 + m2510r0[2]);
        }
        if (str2.charAt(m2510r0[1]) == '/') {
            sb.append((CharSequence) str, 0, m2510r02[1]);
            sb.append(str2);
            return m2508q1(sb, m2510r02[1], m2510r02[1] + m2510r0[2]);
        }
        if (m2510r02[0] + 2 < m2510r02[1] && m2510r02[1] == m2510r02[2]) {
            sb.append((CharSequence) str, 0, m2510r02[1]);
            sb.append('/');
            sb.append(str2);
            return m2508q1(sb, m2510r02[1], m2510r02[1] + m2510r0[2] + 1);
        }
        int lastIndexOf = str.lastIndexOf(47, m2510r02[2] - 1);
        int i3 = lastIndexOf == -1 ? m2510r02[1] : lastIndexOf + 1;
        sb.append((CharSequence) str, 0, i3);
        sb.append(str2);
        return m2508q1(sb, m2510r02[1], i3 + m2510r0[2]);
    }

    /* renamed from: s */
    public static /* synthetic */ void m2512s(InterfaceC3053d1 interfaceC3053d1, CancellationException cancellationException, int i2, Object obj) {
        int i3 = i2 & 1;
        interfaceC3053d1.mo3551d(null);
    }

    /* renamed from: s0 */
    public static int m2513s0(Activity activity) {
        DisplayMetrics displayMetrics = new DisplayMetrics();
        activity.getWindowManager().getDefaultDisplay().getMetrics(displayMetrics);
        return displayMetrics.heightPixels;
    }

    /* renamed from: s1 */
    public static Uri m2514s1(@androidx.annotation.Nullable String str, @androidx.annotation.Nullable String str2) {
        return Uri.parse(m2511r1(str, str2));
    }

    /* renamed from: t */
    public static /* synthetic */ void m2515t(InterfaceC2994q interfaceC2994q, CancellationException cancellationException, int i2, Object obj) {
        int i3 = i2 & 1;
        interfaceC2994q.mo3458d(null);
    }

    /* renamed from: t0 */
    public static final void m2516t0(@NotNull CoroutineContext coroutineContext, @NotNull Throwable th) {
        try {
            int i2 = CoroutineExceptionHandler.f12112a;
            CoroutineExceptionHandler coroutineExceptionHandler = (CoroutineExceptionHandler) coroutineContext.get(CoroutineExceptionHandler.C4735a.f12113a);
            if (coroutineExceptionHandler != null) {
                coroutineExceptionHandler.handleException(coroutineContext, th);
            } else {
                C3052d0.m3549a(coroutineContext, th);
            }
        } catch (Throwable th2) {
            if (th != th2) {
                RuntimeException runtimeException = new RuntimeException("Exception while trying to handle coroutine exception", th2);
                ExceptionsKt__ExceptionsKt.addSuppressed(runtimeException, th);
                th = runtimeException;
            }
            C3052d0.m3549a(coroutineContext, th);
        }
    }

    /* renamed from: t1 */
    public static final <T> void m2517t1(@NotNull AbstractC3076l0<? super T> abstractC3076l0, @NotNull Continuation<? super T> continuation, boolean z) {
        Object mo3605e;
        Object mo3420k = abstractC3076l0.mo3420k();
        Throwable mo3604d = abstractC3076l0.mo3604d(mo3420k);
        if (mo3604d != null) {
            Result.Companion companion = Result.INSTANCE;
            mo3605e = ResultKt.createFailure(mo3604d);
        } else {
            Result.Companion companion2 = Result.INSTANCE;
            mo3605e = abstractC3076l0.mo3605e(mo3420k);
        }
        Object m6055constructorimpl = Result.m6055constructorimpl(mo3605e);
        if (!z) {
            continuation.resumeWith(m6055constructorimpl);
            return;
        }
        Objects.requireNonNull(continuation, "null cannot be cast to non-null type kotlinx.coroutines.internal.DispatchedContinuation<T>");
        C2957f c2957f = (C2957f) continuation;
        CoroutineContext coroutineContext = c2957f.get$context();
        Object m3414c = C2952a.m3414c(coroutineContext, c2957f.f8105j);
        try {
            c2957f.f8107l.resumeWith(m6055constructorimpl);
            Unit unit = Unit.INSTANCE;
        } finally {
            C2952a.m3412a(coroutineContext, m3414c);
        }
    }

    @PublishedApi
    /* renamed from: u */
    public static final void m2518u(@NotNull InterfaceC2994q<?> interfaceC2994q, @Nullable Throwable th) {
        CancellationException cancellationException = null;
        if (th != null) {
            cancellationException = (CancellationException) (th instanceof CancellationException ? th : null);
            if (cancellationException == null) {
                cancellationException = new CancellationException("Channel was consumed, consumer had failed");
                cancellationException.initCause(th);
            }
        }
        interfaceC2994q.mo3458d(cancellationException);
    }

    /* renamed from: u0 */
    public static int m2519u0(int i2, Object obj) {
        return (i2 * 37) + (obj != null ? obj.hashCode() : 0);
    }

    /* renamed from: u1 */
    public static int m2520u1(float f2) {
        return (int) (f2 + (f2 < 0.0f ? -0.5f : 0.5f));
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x007c  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00a2  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0045  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0024  */
    @org.jetbrains.annotations.Nullable
    /* renamed from: v */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final <T> java.lang.Object m2521v(@org.jetbrains.annotations.NotNull p379c.p380a.p383b2.InterfaceC3006b<? extends T> r5, @org.jetbrains.annotations.NotNull p379c.p380a.p383b2.InterfaceC3007c<? super T> r6, @org.jetbrains.annotations.NotNull kotlin.coroutines.Continuation<? super java.lang.Throwable> r7) {
        /*
            boolean r0 = r7 instanceof p379c.p380a.p383b2.C3012h
            if (r0 == 0) goto L13
            r0 = r7
            c.a.b2.h r0 = (p379c.p380a.p383b2.C3012h) r0
            int r1 = r0.f8241e
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.f8241e = r1
            goto L18
        L13:
            c.a.b2.h r0 = new c.a.b2.h
            r0.<init>(r7)
        L18:
            java.lang.Object r7 = r0.f8240c
            java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r2 = r0.f8241e
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L45
            if (r2 != r4) goto L3d
            java.lang.Object r5 = r0.f8245i
            c.a.b2.b r5 = (p379c.p380a.p383b2.InterfaceC3006b) r5
            java.lang.Object r5 = r0.f8244h
            kotlin.jvm.internal.Ref$ObjectRef r5 = (kotlin.jvm.internal.Ref.ObjectRef) r5
            java.lang.Object r6 = r0.f8243g
            c.a.b2.c r6 = (p379c.p380a.p383b2.InterfaceC3007c) r6
            java.lang.Object r6 = r0.f8242f
            c.a.b2.b r6 = (p379c.p380a.p383b2.InterfaceC3006b) r6
            kotlin.ResultKt.throwOnFailure(r7)     // Catch: java.lang.Throwable -> L3a
            goto L65
        L3a:
            r6 = move-exception
            r1 = r6
            goto L6a
        L3d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L45:
            kotlin.ResultKt.throwOnFailure(r7)
            kotlin.jvm.internal.Ref$ObjectRef r7 = new kotlin.jvm.internal.Ref$ObjectRef
            r7.<init>()
            r7.element = r3
            c.a.b2.g r2 = new c.a.b2.g     // Catch: java.lang.Throwable -> L67
            r2.<init>(r6, r7)     // Catch: java.lang.Throwable -> L67
            r0.f8242f = r5     // Catch: java.lang.Throwable -> L67
            r0.f8243g = r6     // Catch: java.lang.Throwable -> L67
            r0.f8244h = r7     // Catch: java.lang.Throwable -> L67
            r0.f8245i = r5     // Catch: java.lang.Throwable -> L67
            r0.f8241e = r4     // Catch: java.lang.Throwable -> L67
            java.lang.Object r5 = r5.mo289a(r2, r0)     // Catch: java.lang.Throwable -> L67
            if (r5 != r1) goto L65
            goto La1
        L65:
            r1 = r3
            goto La1
        L67:
            r5 = move-exception
            r1 = r5
            r5 = r7
        L6a:
            T r5 = r5.element
            java.lang.Throwable r5 = (java.lang.Throwable) r5
            r6 = 0
            if (r5 == 0) goto L79
            boolean r5 = kotlin.jvm.internal.Intrinsics.areEqual(r5, r1)
            if (r5 == 0) goto L79
            r5 = 1
            goto L7a
        L79:
            r5 = 0
        L7a:
            if (r5 != 0) goto La2
            kotlin.coroutines.CoroutineContext r5 = r0.get$context()
            c.a.d1$a r7 = p379c.p380a.InterfaceC3053d1.f8393b
            kotlin.coroutines.CoroutineContext$Element r5 = r5.get(r7)
            c.a.d1 r5 = (p379c.p380a.InterfaceC3053d1) r5
            if (r5 == 0) goto L9e
            boolean r7 = r5.isCancelled()
            if (r7 != 0) goto L91
            goto L9e
        L91:
            java.util.concurrent.CancellationException r5 = r5.mo3553q()
            if (r5 == 0) goto L9e
            boolean r5 = kotlin.jvm.internal.Intrinsics.areEqual(r5, r1)
            if (r5 == 0) goto L9e
            goto L9f
        L9e:
            r4 = 0
        L9f:
            if (r4 != 0) goto La2
        La1:
            return r1
        La2:
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p250p1.C2354n.m2521v(c.a.b2.b, c.a.b2.c, kotlin.coroutines.Continuation):java.lang.Object");
    }

    /* renamed from: v0 */
    public static int m2522v0(byte b2) {
        int digit = Character.digit((char) b2, 16);
        if (digit != -1) {
            return digit;
        }
        throw new IOException(C1499a.m626l("Invalid quoted printable encoding: not a valid hex digit: ", b2));
    }

    /* renamed from: v1 */
    public static void m2523v1(Context context, Bitmap bitmap, String str) {
        String m637w = C1499a.m637w(str, ".jpg");
        File file = new File(m2492l0().getPath());
        if (!file.exists() ? file.mkdirs() : true) {
            File file2 = new File(file, m637w);
            String absolutePath = file2.getAbsolutePath();
            try {
                FileOutputStream fileOutputStream = new FileOutputStream(file2);
                bitmap.compress(Bitmap.CompressFormat.JPEG, 100, fileOutputStream);
                fileOutputStream.close();
            } catch (Exception e2) {
                e2.printStackTrace();
            }
            Intent intent = new Intent("android.intent.action.MEDIA_SCANNER_SCAN_FILE");
            intent.setData(Uri.fromFile(new File(absolutePath)));
            context.sendBroadcast(intent);
        }
    }

    /* renamed from: w */
    public static void m2524w(boolean z) {
        if (!z) {
            throw new IllegalArgumentException();
        }
    }

    /* renamed from: w0 */
    public static void m2525w0(String str) {
        C4325a.m4901d(MyApp.f9894i, str).show();
    }

    /* renamed from: w1 */
    public static final int m2526w1(@NotNull C4761w segment, int i2) {
        int i3;
        Intrinsics.checkNotNullParameter(segment, "$this$segment");
        int[] binarySearch = segment.f12179j;
        int i4 = i2 + 1;
        int length = segment.f12178i.length;
        Intrinsics.checkNotNullParameter(binarySearch, "$this$binarySearch");
        int i5 = length - 1;
        int i6 = 0;
        while (true) {
            if (i6 <= i5) {
                i3 = (i6 + i5) >>> 1;
                int i7 = binarySearch[i3];
                if (i7 >= i4) {
                    if (i7 <= i4) {
                        break;
                    }
                    i5 = i3 - 1;
                } else {
                    i6 = i3 + 1;
                }
            } else {
                i3 = (-i6) - 1;
                break;
            }
        }
        return i3 >= 0 ? i3 : ~i3;
    }

    /* renamed from: x */
    public static void m2527x() {
        while (true) {
            int glGetError = GLES20.glGetError();
            if (glGetError == 0) {
                return;
            } else {
                GLU.gluErrorString(glGetError);
            }
        }
    }

    /* renamed from: x0 */
    public static int m2528x0(SpannableStringBuilder spannableStringBuilder, int i2, String str, int i3) {
        String str2 = (i3 & 4) != 0 ? ExifInterface.GPS_DIRECTION_TRUE : null;
        Object[] spans = (ReplacementSpan[]) spannableStringBuilder.getSpans(0, spannableStringBuilder.toString().length(), ReplacementSpan.class);
        Intrinsics.checkNotNullExpressionValue(spans, "spans");
        for (Object obj : spans) {
            if (i2 >= spannableStringBuilder.getSpanStart(obj)) {
                i2 = str2.length() + i2;
            }
        }
        spannableStringBuilder.insert(i2, (CharSequence) str2);
        return i2;
    }

    /* renamed from: x1 */
    public static final void m2529x1(TextView textView, SpannableStringBuilder spannableStringBuilder, int i2, int i3, Function0<Unit> function0) {
        if (function0 != null) {
            C1329c c1329c = new C1329c(0, false, 2);
            Intrinsics.checkNotNullParameter(function0, "<set-?>");
            c1329c.f1125f = function0;
            Unit unit = Unit.INSTANCE;
            spannableStringBuilder.setSpan(c1329c, i2, i3, 33);
            textView.setMovementMethod(LinkMovementMethod.getInstance());
        }
    }

    /* renamed from: y */
    public static final void m2530y(long j2, long j3, long j4) {
        if ((j3 | j4) < 0 || j3 > j2 || j2 - j3 < j4) {
            throw new ArrayIndexOutOfBoundsException("size=" + j2 + " offset=" + j3 + " byteCount=" + j4);
        }
    }

    /* renamed from: y0 */
    public static /* synthetic */ InterfaceC3082n0 m2531y0(InterfaceC3053d1 interfaceC3053d1, boolean z, boolean z2, Function1 function1, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = false;
        }
        if ((i2 & 2) != 0) {
            z2 = true;
        }
        return interfaceC3053d1.mo3552o(z, z2, function1);
    }

    @androidx.databinding.BindingAdapter({"imageRes"})
    /* renamed from: y1 */
    public static final void m2532y1(@NotNull ImageView imageView, @DrawableRes int i2) {
        Intrinsics.checkNotNullParameter(imageView, "imageView");
        Intrinsics.stringPlus("setImageRes: ", Integer.valueOf(i2));
        imageView.setImageResource(i2);
    }

    /* renamed from: z */
    public static final <T extends View> void m2533z(@NotNull final T t, long j2, @NotNull final Function1<? super T, Unit> block) {
        Intrinsics.checkNotNullParameter(t, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        t.setTag(1123461123, Long.valueOf(j2));
        t.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.a.c
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                long j3;
                long j4;
                boolean z;
                View this_clickWithTrigger = t;
                Function1 block2 = block;
                Intrinsics.checkNotNullParameter(this_clickWithTrigger, "$this_clickWithTrigger");
                Intrinsics.checkNotNullParameter(block2, "$block");
                long currentTimeMillis = System.currentTimeMillis();
                if (this_clickWithTrigger.getTag(1123460103) != null) {
                    Object tag = this_clickWithTrigger.getTag(1123460103);
                    Objects.requireNonNull(tag, "null cannot be cast to non-null type kotlin.Long");
                    j3 = ((Long) tag).longValue();
                } else {
                    j3 = -601;
                }
                long j5 = currentTimeMillis - j3;
                if (this_clickWithTrigger.getTag(1123461123) != null) {
                    Object tag2 = this_clickWithTrigger.getTag(1123461123);
                    Objects.requireNonNull(tag2, "null cannot be cast to non-null type kotlin.Long");
                    j4 = ((Long) tag2).longValue();
                } else {
                    j4 = 600;
                }
                if (j5 >= j4) {
                    z = true;
                    this_clickWithTrigger.setTag(1123460103, Long.valueOf(currentTimeMillis));
                } else {
                    z = false;
                }
                if (z) {
                    Objects.requireNonNull(view, "null cannot be cast to non-null type T of com.jbzd.media.movecartoons.utils.ViewClickDelayKt.clickWithTrigger$lambda-1");
                    block2.invoke(view);
                }
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x003e  */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0023  */
    @org.jetbrains.annotations.Nullable
    /* renamed from: z0 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final /* synthetic */ <T> java.lang.Object m2534z0(@org.jetbrains.annotations.NotNull p379c.p380a.p383b2.InterfaceC3007c<? super T> r4, @org.jetbrains.annotations.NotNull kotlin.jvm.functions.Function3<? super p379c.p380a.p383b2.InterfaceC3007c<? super T>, ? super java.lang.Throwable, ? super kotlin.coroutines.Continuation<? super kotlin.Unit>, ? extends java.lang.Object> r5, @org.jetbrains.annotations.Nullable java.lang.Throwable r6, @org.jetbrains.annotations.NotNull kotlin.coroutines.Continuation<? super kotlin.Unit> r7) {
        /*
            boolean r0 = r7 instanceof p005b.p199l.p200a.p201a.p250p1.C2354n.f
            if (r0 == 0) goto L13
            r0 = r7
            b.l.a.a.p1.n$f r0 = (p005b.p199l.p200a.p201a.p250p1.C2354n.f) r0
            int r1 = r0.f6102e
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.f6102e = r1
            goto L18
        L13:
            b.l.a.a.p1.n$f r0 = new b.l.a.a.p1.n$f
            r0.<init>(r7)
        L18:
            java.lang.Object r7 = r0.f6101c
            java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r2 = r0.f6102e
            r3 = 1
            if (r2 == 0) goto L3e
            if (r2 != r3) goto L36
            java.lang.Object r4 = r0.f6105h
            r6 = r4
            java.lang.Throwable r6 = (java.lang.Throwable) r6
            java.lang.Object r4 = r0.f6104g
            kotlin.jvm.functions.Function3 r4 = (kotlin.jvm.functions.Function3) r4
            java.lang.Object r4 = r0.f6103f
            c.a.b2.c r4 = (p379c.p380a.p383b2.InterfaceC3007c) r4
            kotlin.ResultKt.throwOnFailure(r7)     // Catch: java.lang.Throwable -> L53
            goto L50
        L36:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L3e:
            kotlin.ResultKt.throwOnFailure(r7)
            r0.f6103f = r4     // Catch: java.lang.Throwable -> L53
            r0.f6104g = r5     // Catch: java.lang.Throwable -> L53
            r0.f6105h = r6     // Catch: java.lang.Throwable -> L53
            r0.f6102e = r3     // Catch: java.lang.Throwable -> L53
            java.lang.Object r4 = r5.invoke(r4, r6, r0)     // Catch: java.lang.Throwable -> L53
            if (r4 != r1) goto L50
            return r1
        L50:
            kotlin.Unit r4 = kotlin.Unit.INSTANCE
            return r4
        L53:
            r4 = move-exception
            if (r6 == 0) goto L5b
            if (r6 == r4) goto L5b
            kotlin.ExceptionsKt__ExceptionsKt.addSuppressed(r4, r6)
        L5b:
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p250p1.C2354n.m2534z0(c.a.b2.c, kotlin.jvm.functions.Function3, java.lang.Throwable, kotlin.coroutines.Continuation):java.lang.Object");
    }

    @androidx.databinding.BindingAdapter({"imageUrl"})
    /* renamed from: z1 */
    public static final void m2535z1(@NotNull ImageView imageView, @Nullable String str) {
        Intrinsics.checkNotNullParameter(imageView, "imageView");
        ComponentCallbacks2C1553c.m739i(imageView).mo775h(str).m757R(imageView);
    }
}
