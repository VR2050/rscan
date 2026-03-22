package kotlin.reflect.jvm.internal.impl.serialization.deserialization;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public interface DeserializationConfiguration {

    public static final class Default implements DeserializationConfiguration {

        @NotNull
        public static final Default INSTANCE = new Default();

        private Default() {
        }

        @Override // kotlin.reflect.jvm.internal.impl.serialization.deserialization.DeserializationConfiguration
        public boolean getAllowUnstableDependencies() {
            return DefaultImpls.getAllowUnstableDependencies(this);
        }

        @Override // kotlin.reflect.jvm.internal.impl.serialization.deserialization.DeserializationConfiguration
        public boolean getPreserveDeclarationsOrdering() {
            return DefaultImpls.getPreserveDeclarationsOrdering(this);
        }

        @Override // kotlin.reflect.jvm.internal.impl.serialization.deserialization.DeserializationConfiguration
        public boolean getReleaseCoroutines() {
            return DefaultImpls.getReleaseCoroutines(this);
        }

        @Override // kotlin.reflect.jvm.internal.impl.serialization.deserialization.DeserializationConfiguration
        public boolean getReportErrorsOnPreReleaseDependencies() {
            return DefaultImpls.getReportErrorsOnPreReleaseDependencies(this);
        }

        @Override // kotlin.reflect.jvm.internal.impl.serialization.deserialization.DeserializationConfiguration
        public boolean getSkipMetadataVersionCheck() {
            return DefaultImpls.getSkipMetadataVersionCheck(this);
        }

        @Override // kotlin.reflect.jvm.internal.impl.serialization.deserialization.DeserializationConfiguration
        public boolean getSkipPrereleaseCheck() {
            return DefaultImpls.getSkipPrereleaseCheck(this);
        }

        @Override // kotlin.reflect.jvm.internal.impl.serialization.deserialization.DeserializationConfiguration
        public boolean getTypeAliasesAllowed() {
            return DefaultImpls.getTypeAliasesAllowed(this);
        }
    }

    public static final class DefaultImpls {
        public static boolean getAllowUnstableDependencies(@NotNull DeserializationConfiguration deserializationConfiguration) {
            Intrinsics.checkNotNullParameter(deserializationConfiguration, "this");
            return false;
        }

        public static boolean getPreserveDeclarationsOrdering(@NotNull DeserializationConfiguration deserializationConfiguration) {
            Intrinsics.checkNotNullParameter(deserializationConfiguration, "this");
            return false;
        }

        public static boolean getReleaseCoroutines(@NotNull DeserializationConfiguration deserializationConfiguration) {
            Intrinsics.checkNotNullParameter(deserializationConfiguration, "this");
            return false;
        }

        public static boolean getReportErrorsOnPreReleaseDependencies(@NotNull DeserializationConfiguration deserializationConfiguration) {
            Intrinsics.checkNotNullParameter(deserializationConfiguration, "this");
            return false;
        }

        public static boolean getSkipMetadataVersionCheck(@NotNull DeserializationConfiguration deserializationConfiguration) {
            Intrinsics.checkNotNullParameter(deserializationConfiguration, "this");
            return false;
        }

        public static boolean getSkipPrereleaseCheck(@NotNull DeserializationConfiguration deserializationConfiguration) {
            Intrinsics.checkNotNullParameter(deserializationConfiguration, "this");
            return false;
        }

        public static boolean getTypeAliasesAllowed(@NotNull DeserializationConfiguration deserializationConfiguration) {
            Intrinsics.checkNotNullParameter(deserializationConfiguration, "this");
            return true;
        }
    }

    boolean getAllowUnstableDependencies();

    boolean getPreserveDeclarationsOrdering();

    boolean getReleaseCoroutines();

    boolean getReportErrorsOnPreReleaseDependencies();

    boolean getSkipMetadataVersionCheck();

    boolean getSkipPrereleaseCheck();

    boolean getTypeAliasesAllowed();
}
