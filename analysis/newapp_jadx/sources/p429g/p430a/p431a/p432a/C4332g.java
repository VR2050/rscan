package p429g.p430a.p431a.p432a;

import android.util.Patterns;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: g.a.a.a.g */
/* loaded from: classes2.dex */
public final class C4332g {

    /* renamed from: a */
    public static final Pattern f11181a = Pattern.compile("(^|[\\s.:;?\\-\\]<\\(])((https?://|www\\.|pic\\.)[-\\w;/?:@&=+$\\|\\_.!~*\\|'()\\[\\]%#,☺]+[\\w/#](\\(\\))?)(?=$|[\\s',\\|\\(\\).:;?\\-\\[\\]>\\)])");

    /* renamed from: b */
    @NotNull
    public static final Pattern f11182b;

    /* renamed from: c */
    @NotNull
    public static final Pattern f11183c;

    /* renamed from: d */
    @NotNull
    public static final Pattern f11184d;

    /* renamed from: e */
    @NotNull
    public static final Pattern f11185e;

    static {
        Pattern pattern = Patterns.PHONE;
        Intrinsics.checkNotNullExpressionValue(pattern, "Patterns.PHONE");
        f11182b = pattern;
        Pattern pattern2 = Patterns.EMAIL_ADDRESS;
        Intrinsics.checkNotNullExpressionValue(pattern2, "Patterns.EMAIL_ADDRESS");
        f11183c = pattern2;
        Pattern compile = Pattern.compile("(?:^|\\s|$|[.])@[\\p{L}0-9_]*");
        Intrinsics.checkNotNullExpressionValue(compile, "Pattern.compile(\"(?:^|\\\\s|$|[.])@[\\\\p{L}0-9_]*\")");
        f11184d = compile;
        Pattern compile2 = Pattern.compile("(?<![a-zA-Z0-9_])#(?=[0-9_]*[a-zA-Z])[a-zA-Z0-9_]+");
        Intrinsics.checkNotNullExpressionValue(compile2, "Pattern.compile(\"(?<![a-…*[a-zA-Z])[a-zA-Z0-9_]+\")");
        f11185e = compile2;
    }
}
