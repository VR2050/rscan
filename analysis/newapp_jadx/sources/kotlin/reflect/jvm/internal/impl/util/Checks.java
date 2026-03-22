package kotlin.reflect.jvm.internal.impl.util;

import java.util.Collection;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.descriptors.FunctionDescriptor;
import kotlin.reflect.jvm.internal.impl.name.Name;
import kotlin.reflect.jvm.internal.impl.util.CheckResult;
import kotlin.text.Regex;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* loaded from: classes.dex */
public final class Checks {

    @NotNull
    private final Function1<FunctionDescriptor, String> additionalCheck;

    @NotNull
    private final Check[] checks;

    @Nullable
    private final Name name;

    @Nullable
    private final Collection<Name> nameList;

    @Nullable
    private final Regex regex;

    /* JADX WARN: Multi-variable type inference failed */
    private Checks(Name name, Regex regex, Collection<Name> collection, Function1<? super FunctionDescriptor, String> function1, Check... checkArr) {
        this.name = name;
        this.regex = regex;
        this.nameList = collection;
        this.additionalCheck = function1;
        this.checks = checkArr;
    }

    @NotNull
    public final CheckResult checkAll(@NotNull FunctionDescriptor functionDescriptor) {
        Intrinsics.checkNotNullParameter(functionDescriptor, "functionDescriptor");
        Check[] checkArr = this.checks;
        int length = checkArr.length;
        int i2 = 0;
        while (i2 < length) {
            Check check = checkArr[i2];
            i2++;
            String invoke = check.invoke(functionDescriptor);
            if (invoke != null) {
                return new CheckResult.IllegalSignature(invoke);
            }
        }
        String invoke2 = this.additionalCheck.invoke(functionDescriptor);
        return invoke2 != null ? new CheckResult.IllegalSignature(invoke2) : CheckResult.SuccessCheck.INSTANCE;
    }

    public final boolean isApplicable(@NotNull FunctionDescriptor functionDescriptor) {
        Intrinsics.checkNotNullParameter(functionDescriptor, "functionDescriptor");
        if (this.name != null && !Intrinsics.areEqual(functionDescriptor.getName(), this.name)) {
            return false;
        }
        if (this.regex != null) {
            String asString = functionDescriptor.getName().asString();
            Intrinsics.checkNotNullExpressionValue(asString, "functionDescriptor.name.asString()");
            if (!this.regex.matches(asString)) {
                return false;
            }
        }
        Collection<Name> collection = this.nameList;
        return collection == null || collection.contains(functionDescriptor.getName());
    }

    public /* synthetic */ Checks(Name name, Check[] checkArr, Function1 function1, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(name, checkArr, (Function1<? super FunctionDescriptor, String>) ((i2 & 4) != 0 ? new Function1() { // from class: kotlin.reflect.jvm.internal.impl.util.Checks.2
            @Override // kotlin.jvm.functions.Function1
            @Nullable
            public final Void invoke(@NotNull FunctionDescriptor functionDescriptor) {
                Intrinsics.checkNotNullParameter(functionDescriptor, "$this$null");
                return null;
            }
        } : function1));
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public Checks(@org.jetbrains.annotations.NotNull kotlin.reflect.jvm.internal.impl.name.Name r8, @org.jetbrains.annotations.NotNull kotlin.reflect.jvm.internal.impl.util.Check[] r9, @org.jetbrains.annotations.NotNull kotlin.jvm.functions.Function1<? super kotlin.reflect.jvm.internal.impl.descriptors.FunctionDescriptor, java.lang.String> r10) {
        /*
            r7 = this;
            java.lang.String r0 = "name"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r0)
            java.lang.String r0 = "checks"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            java.lang.String r0 = "additionalChecks"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r0)
            int r0 = r9.length
            kotlin.reflect.jvm.internal.impl.util.Check[] r6 = new kotlin.reflect.jvm.internal.impl.util.Check[r0]
            int r0 = r9.length
            r1 = 0
            java.lang.System.arraycopy(r9, r1, r6, r1, r0)
            r3 = 0
            r4 = 0
            r1 = r7
            r2 = r8
            r5 = r10
            r1.<init>(r2, r3, r4, r5, r6)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.reflect.jvm.internal.impl.util.Checks.<init>(kotlin.reflect.jvm.internal.impl.name.Name, kotlin.reflect.jvm.internal.impl.util.Check[], kotlin.jvm.functions.Function1):void");
    }

    public /* synthetic */ Checks(Regex regex, Check[] checkArr, Function1 function1, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(regex, checkArr, (Function1<? super FunctionDescriptor, String>) ((i2 & 4) != 0 ? new Function1() { // from class: kotlin.reflect.jvm.internal.impl.util.Checks.3
            @Override // kotlin.jvm.functions.Function1
            @Nullable
            public final Void invoke(@NotNull FunctionDescriptor functionDescriptor) {
                Intrinsics.checkNotNullParameter(functionDescriptor, "$this$null");
                return null;
            }
        } : function1));
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public Checks(@org.jetbrains.annotations.NotNull kotlin.text.Regex r8, @org.jetbrains.annotations.NotNull kotlin.reflect.jvm.internal.impl.util.Check[] r9, @org.jetbrains.annotations.NotNull kotlin.jvm.functions.Function1<? super kotlin.reflect.jvm.internal.impl.descriptors.FunctionDescriptor, java.lang.String> r10) {
        /*
            r7 = this;
            java.lang.String r0 = "regex"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r0)
            java.lang.String r0 = "checks"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            java.lang.String r0 = "additionalChecks"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r0)
            int r0 = r9.length
            kotlin.reflect.jvm.internal.impl.util.Check[] r6 = new kotlin.reflect.jvm.internal.impl.util.Check[r0]
            int r0 = r9.length
            r1 = 0
            java.lang.System.arraycopy(r9, r1, r6, r1, r0)
            r2 = 0
            r4 = 0
            r1 = r7
            r3 = r8
            r5 = r10
            r1.<init>(r2, r3, r4, r5, r6)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.reflect.jvm.internal.impl.util.Checks.<init>(kotlin.text.Regex, kotlin.reflect.jvm.internal.impl.util.Check[], kotlin.jvm.functions.Function1):void");
    }

    public /* synthetic */ Checks(Collection collection, Check[] checkArr, Function1 function1, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((Collection<Name>) collection, checkArr, (Function1<? super FunctionDescriptor, String>) ((i2 & 4) != 0 ? new Function1() { // from class: kotlin.reflect.jvm.internal.impl.util.Checks.4
            @Override // kotlin.jvm.functions.Function1
            @Nullable
            public final Void invoke(@NotNull FunctionDescriptor functionDescriptor) {
                Intrinsics.checkNotNullParameter(functionDescriptor, "$this$null");
                return null;
            }
        } : function1));
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public Checks(@org.jetbrains.annotations.NotNull java.util.Collection<kotlin.reflect.jvm.internal.impl.name.Name> r8, @org.jetbrains.annotations.NotNull kotlin.reflect.jvm.internal.impl.util.Check[] r9, @org.jetbrains.annotations.NotNull kotlin.jvm.functions.Function1<? super kotlin.reflect.jvm.internal.impl.descriptors.FunctionDescriptor, java.lang.String> r10) {
        /*
            r7 = this;
            java.lang.String r0 = "nameList"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r0)
            java.lang.String r0 = "checks"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            java.lang.String r0 = "additionalChecks"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r0)
            int r0 = r9.length
            kotlin.reflect.jvm.internal.impl.util.Check[] r6 = new kotlin.reflect.jvm.internal.impl.util.Check[r0]
            int r0 = r9.length
            r1 = 0
            java.lang.System.arraycopy(r9, r1, r6, r1, r0)
            r2 = 0
            r3 = 0
            r1 = r7
            r4 = r8
            r5 = r10
            r1.<init>(r2, r3, r4, r5, r6)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.reflect.jvm.internal.impl.util.Checks.<init>(java.util.Collection, kotlin.reflect.jvm.internal.impl.util.Check[], kotlin.jvm.functions.Function1):void");
    }
}
