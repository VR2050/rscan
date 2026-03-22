package p458k;

import kotlin.Deprecated;
import kotlin.DeprecationLevel;
import kotlin.ReplaceWith;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.p459p0.C4401c;
import p474l.InterfaceC4745g;

/* renamed from: k.j0 */
/* loaded from: classes3.dex */
public abstract class AbstractC4387j0 {

    /* renamed from: a */
    public static final a f11483a = new a(null);

    /* renamed from: k.j0$a */
    public static final class a {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }
    }

    @JvmStatic
    @NotNull
    @Deprecated(level = DeprecationLevel.WARNING, message = "Moved to extension function. Put the 'content' argument first to fix Java", replaceWith = @ReplaceWith(expression = "content.toRequestBody(contentType, offset, byteCount)", imports = {"okhttp3.RequestBody.Companion.toRequestBody"}))
    @JvmOverloads
    /* renamed from: c */
    public static final AbstractC4387j0 m4986c(@Nullable C4371b0 c4371b0, @NotNull byte[] toRequestBody) {
        int i2 = 12 & 4;
        int length = (12 & 8) != 0 ? toRequestBody.length : 0;
        Intrinsics.checkParameterIsNotNull(toRequestBody, "content");
        Intrinsics.checkParameterIsNotNull(toRequestBody, "$this$toRequestBody");
        C4401c.m5018c(toRequestBody.length, 0, length);
        return new C4385i0(toRequestBody, c4371b0, length, 0);
    }

    /* renamed from: a */
    public long mo4920a() {
        return -1L;
    }

    @Nullable
    /* renamed from: b */
    public abstract C4371b0 mo4921b();

    /* renamed from: d */
    public abstract void mo4922d(@NotNull InterfaceC4745g interfaceC4745g);
}
