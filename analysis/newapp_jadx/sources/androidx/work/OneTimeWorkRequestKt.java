package androidx.work;

import androidx.annotation.NonNull;
import androidx.exifinterface.media.ExifInterface;
import androidx.work.OneTimeWorkRequest;
import kotlin.Metadata;
import kotlin.jvm.JvmClassMappingKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.KClass;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\u001a\u001c\u0010\u0003\u001a\u00020\u0002\"\n\b\u0000\u0010\u0001\u0018\u0001*\u00020\u0000H\u0086\b¢\u0006\u0004\b\u0003\u0010\u0004\u001a&\u0010\b\u001a\u00020\u0002*\u00020\u00022\u0010\b\u0001\u0010\u0007\u001a\n\u0012\u0006\b\u0001\u0012\u00020\u00060\u0005H\u0086\b¢\u0006\u0004\b\b\u0010\t¨\u0006\n"}, m5311d2 = {"Landroidx/work/ListenableWorker;", ExifInterface.LONGITUDE_WEST, "Landroidx/work/OneTimeWorkRequest$Builder;", "OneTimeWorkRequestBuilder", "()Landroidx/work/OneTimeWorkRequest$Builder;", "Lkotlin/reflect/KClass;", "Landroidx/work/InputMerger;", "inputMerger", "setInputMerger", "(Landroidx/work/OneTimeWorkRequest$Builder;Lkotlin/reflect/KClass;)Landroidx/work/OneTimeWorkRequest$Builder;", "work-runtime-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class OneTimeWorkRequestKt {
    @NotNull
    public static final /* synthetic */ <W extends ListenableWorker> OneTimeWorkRequest.Builder OneTimeWorkRequestBuilder() {
        Intrinsics.reifiedOperationMarker(4, ExifInterface.LONGITUDE_WEST);
        return new OneTimeWorkRequest.Builder(ListenableWorker.class);
    }

    @NotNull
    public static final OneTimeWorkRequest.Builder setInputMerger(@NotNull OneTimeWorkRequest.Builder setInputMerger, @NonNull @NotNull KClass<? extends InputMerger> inputMerger) {
        Intrinsics.checkParameterIsNotNull(setInputMerger, "$this$setInputMerger");
        Intrinsics.checkParameterIsNotNull(inputMerger, "inputMerger");
        OneTimeWorkRequest.Builder inputMerger2 = setInputMerger.setInputMerger(JvmClassMappingKt.getJavaClass((KClass) inputMerger));
        Intrinsics.checkExpressionValueIsNotNull(inputMerger2, "setInputMerger(inputMerger.java)");
        return inputMerger2;
    }
}
