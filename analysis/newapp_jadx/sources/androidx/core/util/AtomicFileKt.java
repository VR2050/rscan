package androidx.core.util;

import androidx.annotation.RequiresApi;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.InlineMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u0012\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\b\u001a:\u0010\b\u001a\u00020\u0006*\u00020\u00002!\u0010\u0007\u001a\u001d\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b\u0003\u0012\b\b\u0004\u0012\u0004\b\b(\u0005\u0012\u0004\u0012\u00020\u00060\u0001H\u0087\bø\u0001\u0000¢\u0006\u0004\b\b\u0010\t\u001a\u001b\u0010\f\u001a\u00020\u0006*\u00020\u00002\u0006\u0010\u000b\u001a\u00020\nH\u0007¢\u0006\u0004\b\f\u0010\r\u001a%\u0010\u0012\u001a\u00020\u0006*\u00020\u00002\u0006\u0010\u000f\u001a\u00020\u000e2\b\b\u0002\u0010\u0011\u001a\u00020\u0010H\u0007¢\u0006\u0004\b\u0012\u0010\u0013\u001a\u0014\u0010\u0014\u001a\u00020\n*\u00020\u0000H\u0087\b¢\u0006\u0004\b\u0014\u0010\u0015\u001a\u001d\u0010\u0016\u001a\u00020\u000e*\u00020\u00002\b\b\u0002\u0010\u0011\u001a\u00020\u0010H\u0007¢\u0006\u0004\b\u0016\u0010\u0017\u0082\u0002\u0007\n\u0005\b\u009920\u0001¨\u0006\u0018"}, m5311d2 = {"Landroid/util/AtomicFile;", "Lkotlin/Function1;", "Ljava/io/FileOutputStream;", "Lkotlin/ParameterName;", "name", "out", "", "block", "tryWrite", "(Landroid/util/AtomicFile;Lkotlin/jvm/functions/Function1;)V", "", "array", "writeBytes", "(Landroid/util/AtomicFile;[B)V", "", "text", "Ljava/nio/charset/Charset;", "charset", "writeText", "(Landroid/util/AtomicFile;Ljava/lang/String;Ljava/nio/charset/Charset;)V", "readBytes", "(Landroid/util/AtomicFile;)[B", "readText", "(Landroid/util/AtomicFile;Ljava/nio/charset/Charset;)Ljava/lang/String;", "core-ktx_release"}, m5312k = 2, m5313mv = {1, 5, 1})
/* loaded from: classes.dex */
public final class AtomicFileKt {
    @RequiresApi(17)
    @NotNull
    public static final byte[] readBytes(@NotNull android.util.AtomicFile atomicFile) {
        Intrinsics.checkNotNullParameter(atomicFile, "<this>");
        byte[] readFully = atomicFile.readFully();
        Intrinsics.checkNotNullExpressionValue(readFully, "readFully()");
        return readFully;
    }

    @RequiresApi(17)
    @NotNull
    public static final String readText(@NotNull android.util.AtomicFile atomicFile, @NotNull Charset charset) {
        Intrinsics.checkNotNullParameter(atomicFile, "<this>");
        Intrinsics.checkNotNullParameter(charset, "charset");
        byte[] readFully = atomicFile.readFully();
        Intrinsics.checkNotNullExpressionValue(readFully, "readFully()");
        return new String(readFully, charset);
    }

    public static /* synthetic */ String readText$default(android.util.AtomicFile atomicFile, Charset charset, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            charset = Charsets.UTF_8;
        }
        return readText(atomicFile, charset);
    }

    @RequiresApi(17)
    public static final void tryWrite(@NotNull android.util.AtomicFile atomicFile, @NotNull Function1<? super FileOutputStream, Unit> block) {
        Intrinsics.checkNotNullParameter(atomicFile, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        FileOutputStream stream = atomicFile.startWrite();
        try {
            Intrinsics.checkNotNullExpressionValue(stream, "stream");
            block.invoke(stream);
            InlineMarker.finallyStart(1);
            atomicFile.finishWrite(stream);
            InlineMarker.finallyEnd(1);
        } catch (Throwable th) {
            InlineMarker.finallyStart(1);
            atomicFile.failWrite(stream);
            InlineMarker.finallyEnd(1);
            throw th;
        }
    }

    @RequiresApi(17)
    public static final void writeBytes(@NotNull android.util.AtomicFile atomicFile, @NotNull byte[] array) {
        Intrinsics.checkNotNullParameter(atomicFile, "<this>");
        Intrinsics.checkNotNullParameter(array, "array");
        FileOutputStream stream = atomicFile.startWrite();
        try {
            Intrinsics.checkNotNullExpressionValue(stream, "stream");
            stream.write(array);
            atomicFile.finishWrite(stream);
        } catch (Throwable th) {
            atomicFile.failWrite(stream);
            throw th;
        }
    }

    @RequiresApi(17)
    public static final void writeText(@NotNull android.util.AtomicFile atomicFile, @NotNull String text, @NotNull Charset charset) {
        Intrinsics.checkNotNullParameter(atomicFile, "<this>");
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(charset, "charset");
        byte[] bytes = text.getBytes(charset);
        Intrinsics.checkNotNullExpressionValue(bytes, "(this as java.lang.String).getBytes(charset)");
        writeBytes(atomicFile, bytes);
    }

    public static /* synthetic */ void writeText$default(android.util.AtomicFile atomicFile, String str, Charset charset, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            charset = Charsets.UTF_8;
        }
        writeText(atomicFile, str, charset);
    }
}
