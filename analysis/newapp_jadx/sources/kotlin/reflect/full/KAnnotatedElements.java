package kotlin.reflect.full;

import androidx.exifinterface.media.ExifInterface;
import java.lang.annotation.Annotation;
import java.util.Iterator;
import kotlin.ExperimentalStdlibApi;
import kotlin.Metadata;
import kotlin.SinceKotlin;
import kotlin.WasExperimental;
import kotlin.jvm.JvmName;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.KAnnotatedElement;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0010\u001b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0003\u001a\"\u0010\u0003\u001a\u0004\u0018\u00018\u0000\"\n\b\u0000\u0010\u0001\u0018\u0001*\u00020\u0000*\u00020\u0002H\u0087\b¢\u0006\u0004\b\u0003\u0010\u0004\u001a \u0010\u0006\u001a\u00020\u0005\"\n\b\u0000\u0010\u0001\u0018\u0001*\u00020\u0000*\u00020\u0002H\u0087\b¢\u0006\u0004\b\u0006\u0010\u0007¨\u0006\b"}, m5311d2 = {"", ExifInterface.GPS_DIRECTION_TRUE, "Lkotlin/reflect/KAnnotatedElement;", "findAnnotation", "(Lkotlin/reflect/KAnnotatedElement;)Ljava/lang/annotation/Annotation;", "", "hasAnnotation", "(Lkotlin/reflect/KAnnotatedElement;)Z", "kotlin-reflection"}, m5312k = 2, m5313mv = {1, 5, 1})
@JvmName(name = "KAnnotatedElements")
/* loaded from: classes2.dex */
public final class KAnnotatedElements {
    @SinceKotlin(version = "1.1")
    public static final /* synthetic */ <T extends Annotation> T findAnnotation(KAnnotatedElement findAnnotation) {
        Object obj;
        Intrinsics.checkNotNullParameter(findAnnotation, "$this$findAnnotation");
        Iterator<T> it = findAnnotation.getAnnotations().iterator();
        while (true) {
            if (!it.hasNext()) {
                obj = null;
                break;
            }
            obj = it.next();
            Intrinsics.reifiedOperationMarker(3, ExifInterface.GPS_DIRECTION_TRUE);
            if (((Annotation) obj) instanceof Annotation) {
                break;
            }
        }
        Intrinsics.reifiedOperationMarker(1, "T?");
        return (T) obj;
    }

    @SinceKotlin(version = "1.4")
    @WasExperimental(markerClass = {ExperimentalStdlibApi.class})
    public static final /* synthetic */ <T extends Annotation> boolean hasAnnotation(KAnnotatedElement hasAnnotation) {
        Object obj;
        Intrinsics.checkNotNullParameter(hasAnnotation, "$this$hasAnnotation");
        Iterator<T> it = hasAnnotation.getAnnotations().iterator();
        while (true) {
            if (!it.hasNext()) {
                obj = null;
                break;
            }
            obj = it.next();
            Intrinsics.reifiedOperationMarker(3, ExifInterface.GPS_DIRECTION_TRUE);
            if (((Annotation) obj) instanceof Annotation) {
                break;
            }
        }
        Intrinsics.reifiedOperationMarker(1, "T?");
        return ((Annotation) obj) != null;
    }
}
