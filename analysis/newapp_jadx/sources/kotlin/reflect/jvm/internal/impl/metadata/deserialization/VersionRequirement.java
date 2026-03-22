package kotlin.reflect.jvm.internal.impl.metadata.deserialization;

import java.util.ArrayList;
import java.util.List;
import kotlin.DeprecationLevel;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.metadata.ProtoBuf;
import kotlin.reflect.jvm.internal.impl.protobuf.MessageLite;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class VersionRequirement {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @Nullable
    private final Integer errorCode;

    @NotNull
    private final ProtoBuf.VersionRequirement.VersionKind kind;

    @NotNull
    private final DeprecationLevel level;

    @Nullable
    private final String message;

    @NotNull
    private final Version version;

    public static final class Version {

        @NotNull
        public static final Companion Companion = new Companion(null);

        @JvmField
        @NotNull
        public static final Version INFINITY = new Version(256, 256, 256);
        private final int major;
        private final int minor;
        private final int patch;

        public static final class Companion {
            private Companion() {
            }

            public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
                this();
            }

            @NotNull
            public final Version decode(@Nullable Integer num, @Nullable Integer num2) {
                return num2 != null ? new Version(num2.intValue() & 255, (num2.intValue() >> 8) & 255, (num2.intValue() >> 16) & 255) : num != null ? new Version(num.intValue() & 7, (num.intValue() >> 3) & 15, (num.intValue() >> 7) & 127) : Version.INFINITY;
            }
        }

        public Version(int i2, int i3, int i4) {
            this.major = i2;
            this.minor = i3;
            this.patch = i4;
        }

        @NotNull
        public final String asString() {
            StringBuilder sb;
            int i2;
            if (this.patch == 0) {
                sb = new StringBuilder();
                sb.append(this.major);
                sb.append('.');
                i2 = this.minor;
            } else {
                sb = new StringBuilder();
                sb.append(this.major);
                sb.append('.');
                sb.append(this.minor);
                sb.append('.');
                i2 = this.patch;
            }
            sb.append(i2);
            return sb.toString();
        }

        public boolean equals(@Nullable Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Version)) {
                return false;
            }
            Version version = (Version) obj;
            return this.major == version.major && this.minor == version.minor && this.patch == version.patch;
        }

        public int hashCode() {
            return (((this.major * 31) + this.minor) * 31) + this.patch;
        }

        @NotNull
        public String toString() {
            return asString();
        }

        public /* synthetic */ Version(int i2, int i3, int i4, int i5, DefaultConstructorMarker defaultConstructorMarker) {
            this(i2, i3, (i5 & 4) != 0 ? 0 : i4);
        }
    }

    public VersionRequirement(@NotNull Version version, @NotNull ProtoBuf.VersionRequirement.VersionKind kind, @NotNull DeprecationLevel level, @Nullable Integer num, @Nullable String str) {
        Intrinsics.checkNotNullParameter(version, "version");
        Intrinsics.checkNotNullParameter(kind, "kind");
        Intrinsics.checkNotNullParameter(level, "level");
        this.version = version;
        this.kind = kind;
        this.level = level;
        this.errorCode = num;
        this.message = str;
    }

    @NotNull
    public final ProtoBuf.VersionRequirement.VersionKind getKind() {
        return this.kind;
    }

    @NotNull
    public final Version getVersion() {
        return this.version;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("since ");
        m586H.append(this.version);
        m586H.append(' ');
        m586H.append(this.level);
        Integer num = this.errorCode;
        m586H.append(num != null ? Intrinsics.stringPlus(" error ", num) : "");
        String str = this.message;
        m586H.append(str != null ? Intrinsics.stringPlus(": ", str) : "");
        return m586H.toString();
    }

    public static final class Companion {

        public /* synthetic */ class WhenMappings {
            public static final /* synthetic */ int[] $EnumSwitchMapping$0;

            static {
                ProtoBuf.VersionRequirement.Level.values();
                int[] iArr = new int[3];
                iArr[ProtoBuf.VersionRequirement.Level.WARNING.ordinal()] = 1;
                iArr[ProtoBuf.VersionRequirement.Level.ERROR.ordinal()] = 2;
                iArr[ProtoBuf.VersionRequirement.Level.HIDDEN.ordinal()] = 3;
                $EnumSwitchMapping$0 = iArr;
            }
        }

        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final List<VersionRequirement> create(@NotNull MessageLite proto, @NotNull NameResolver nameResolver, @NotNull VersionRequirementTable table) {
            List<Integer> ids;
            Intrinsics.checkNotNullParameter(proto, "proto");
            Intrinsics.checkNotNullParameter(nameResolver, "nameResolver");
            Intrinsics.checkNotNullParameter(table, "table");
            if (proto instanceof ProtoBuf.Class) {
                ids = ((ProtoBuf.Class) proto).getVersionRequirementList();
            } else if (proto instanceof ProtoBuf.Constructor) {
                ids = ((ProtoBuf.Constructor) proto).getVersionRequirementList();
            } else if (proto instanceof ProtoBuf.Function) {
                ids = ((ProtoBuf.Function) proto).getVersionRequirementList();
            } else if (proto instanceof ProtoBuf.Property) {
                ids = ((ProtoBuf.Property) proto).getVersionRequirementList();
            } else {
                if (!(proto instanceof ProtoBuf.TypeAlias)) {
                    throw new IllegalStateException(Intrinsics.stringPlus("Unexpected declaration: ", proto.getClass()));
                }
                ids = ((ProtoBuf.TypeAlias) proto).getVersionRequirementList();
            }
            Intrinsics.checkNotNullExpressionValue(ids, "ids");
            ArrayList arrayList = new ArrayList();
            for (Integer id : ids) {
                Companion companion = VersionRequirement.Companion;
                Intrinsics.checkNotNullExpressionValue(id, "id");
                VersionRequirement create = companion.create(id.intValue(), nameResolver, table);
                if (create != null) {
                    arrayList.add(create);
                }
            }
            return arrayList;
        }

        @Nullable
        public final VersionRequirement create(int i2, @NotNull NameResolver nameResolver, @NotNull VersionRequirementTable table) {
            DeprecationLevel deprecationLevel;
            Intrinsics.checkNotNullParameter(nameResolver, "nameResolver");
            Intrinsics.checkNotNullParameter(table, "table");
            ProtoBuf.VersionRequirement versionRequirement = table.get(i2);
            if (versionRequirement == null) {
                return null;
            }
            Version decode = Version.Companion.decode(versionRequirement.hasVersion() ? Integer.valueOf(versionRequirement.getVersion()) : null, versionRequirement.hasVersionFull() ? Integer.valueOf(versionRequirement.getVersionFull()) : null);
            ProtoBuf.VersionRequirement.Level level = versionRequirement.getLevel();
            Intrinsics.checkNotNull(level);
            int ordinal = level.ordinal();
            if (ordinal == 0) {
                deprecationLevel = DeprecationLevel.WARNING;
            } else if (ordinal == 1) {
                deprecationLevel = DeprecationLevel.ERROR;
            } else {
                if (ordinal != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                deprecationLevel = DeprecationLevel.HIDDEN;
            }
            DeprecationLevel deprecationLevel2 = deprecationLevel;
            Integer valueOf = versionRequirement.hasErrorCode() ? Integer.valueOf(versionRequirement.getErrorCode()) : null;
            String string = versionRequirement.hasMessage() ? nameResolver.getString(versionRequirement.getMessage()) : null;
            ProtoBuf.VersionRequirement.VersionKind versionKind = versionRequirement.getVersionKind();
            Intrinsics.checkNotNullExpressionValue(versionKind, "info.versionKind");
            return new VersionRequirement(decode, versionKind, deprecationLevel2, valueOf, string);
        }
    }
}
