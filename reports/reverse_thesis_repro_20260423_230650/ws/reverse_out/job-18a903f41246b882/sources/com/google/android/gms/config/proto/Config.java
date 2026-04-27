package com.google.android.gms.config.proto;

import com.google.android.exoplayer2.extractor.ts.TsExtractor;
import com.google.android.gms.config.proto.Logs;
import com.google.protobuf.AbstractMessageLite;
import com.google.protobuf.ByteString;
import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.GeneratedMessageLite;
import com.google.protobuf.Internal;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLiteOrBuilder;
import com.google.protobuf.Parser;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;

/* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
/* JADX INFO: loaded from: classes.dex */
public final class Config {

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public interface AppConfigTableOrBuilder extends MessageLiteOrBuilder {
        String getAppName();

        ByteString getAppNameBytes();

        ByteString getExperimentPayload(int i);

        int getExperimentPayloadCount();

        List<ByteString> getExperimentPayloadList();

        AppNamespaceConfigTable getNamespaceConfig(int i);

        int getNamespaceConfigCount();

        List<AppNamespaceConfigTable> getNamespaceConfigList();

        boolean hasAppName();
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public interface AppNamespaceConfigTableOrBuilder extends MessageLiteOrBuilder {
        String getDigest();

        ByteString getDigestBytes();

        KeyValue getEntry(int i);

        int getEntryCount();

        List<KeyValue> getEntryList();

        String getNamespace();

        ByteString getNamespaceBytes();

        AppNamespaceConfigTable.NamespaceStatus getStatus();

        boolean hasDigest();

        boolean hasNamespace();

        boolean hasStatus();
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public interface ConfigFetchRequestOrBuilder extends MessageLiteOrBuilder {
        long getAndroidId();

        int getApiLevel();

        int getClientVersion();

        Logs.AndroidConfigFetchProto getConfig();

        String getDeviceCountry();

        ByteString getDeviceCountryBytes();

        String getDeviceDataVersionInfo();

        ByteString getDeviceDataVersionInfoBytes();

        String getDeviceLocale();

        ByteString getDeviceLocaleBytes();

        int getDeviceSubtype();

        String getDeviceTimezoneId();

        ByteString getDeviceTimezoneIdBytes();

        int getDeviceType();

        int getGmsCoreVersion();

        String getOsVersion();

        ByteString getOsVersionBytes();

        PackageData getPackageData(int i);

        int getPackageDataCount();

        List<PackageData> getPackageDataList();

        long getSecurityToken();

        boolean hasAndroidId();

        boolean hasApiLevel();

        boolean hasClientVersion();

        boolean hasConfig();

        boolean hasDeviceCountry();

        boolean hasDeviceDataVersionInfo();

        boolean hasDeviceLocale();

        boolean hasDeviceSubtype();

        boolean hasDeviceTimezoneId();

        boolean hasDeviceType();

        boolean hasGmsCoreVersion();

        boolean hasOsVersion();

        boolean hasSecurityToken();
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public interface ConfigFetchResponseOrBuilder extends MessageLiteOrBuilder {
        AppConfigTable getAppConfig(int i);

        int getAppConfigCount();

        List<AppConfigTable> getAppConfigList();

        KeyValue getInternalMetadata(int i);

        int getInternalMetadataCount();

        List<KeyValue> getInternalMetadataList();

        PackageTable getPackageTable(int i);

        int getPackageTableCount();

        List<PackageTable> getPackageTableList();

        ConfigFetchResponse.ResponseStatus getStatus();

        boolean hasStatus();
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public interface KeyValueOrBuilder extends MessageLiteOrBuilder {
        String getKey();

        ByteString getKeyBytes();

        ByteString getValue();

        boolean hasKey();

        boolean hasValue();
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public interface NamedValueOrBuilder extends MessageLiteOrBuilder {
        String getName();

        ByteString getNameBytes();

        String getValue();

        ByteString getValueBytes();

        boolean hasName();

        boolean hasValue();
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public interface PackageDataOrBuilder extends MessageLiteOrBuilder {
        int getActiveConfigAgeSeconds();

        NamedValue getAnalyticsUserProperty(int i);

        int getAnalyticsUserPropertyCount();

        List<NamedValue> getAnalyticsUserPropertyList();

        ByteString getAppCertHash();

        String getAppInstanceId();

        ByteString getAppInstanceIdBytes();

        String getAppInstanceIdToken();

        ByteString getAppInstanceIdTokenBytes();

        String getAppVersion();

        ByteString getAppVersionBytes();

        int getAppVersionCode();

        ByteString getCertHash();

        String getConfigId();

        ByteString getConfigIdBytes();

        NamedValue getCustomVariable(int i);

        int getCustomVariableCount();

        List<NamedValue> getCustomVariableList();

        ByteString getDigest();

        int getFetchedConfigAgeSeconds();

        String getGamesProjectId();

        ByteString getGamesProjectIdBytes();

        String getGmpProjectId();

        ByteString getGmpProjectIdBytes();

        NamedValue getNamespaceDigest(int i);

        int getNamespaceDigestCount();

        List<NamedValue> getNamespaceDigestList();

        String getPackageName();

        ByteString getPackageNameBytes();

        int getRequestedCacheExpirationSeconds();

        String getRequestedHiddenNamespace(int i);

        ByteString getRequestedHiddenNamespaceBytes(int i);

        int getRequestedHiddenNamespaceCount();

        List<String> getRequestedHiddenNamespaceList();

        int getSdkVersion();

        int getVersionCode();

        boolean hasActiveConfigAgeSeconds();

        boolean hasAppCertHash();

        boolean hasAppInstanceId();

        boolean hasAppInstanceIdToken();

        boolean hasAppVersion();

        boolean hasAppVersionCode();

        boolean hasCertHash();

        boolean hasConfigId();

        boolean hasDigest();

        boolean hasFetchedConfigAgeSeconds();

        boolean hasGamesProjectId();

        boolean hasGmpProjectId();

        boolean hasPackageName();

        boolean hasRequestedCacheExpirationSeconds();

        boolean hasSdkVersion();

        boolean hasVersionCode();
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public interface PackageTableOrBuilder extends MessageLiteOrBuilder {
        String getConfigId();

        ByteString getConfigIdBytes();

        KeyValue getEntry(int i);

        int getEntryCount();

        List<KeyValue> getEntryList();

        String getPackageName();

        ByteString getPackageNameBytes();

        boolean hasConfigId();

        boolean hasPackageName();
    }

    private Config() {
    }

    public static void registerAllExtensions(ExtensionRegistryLite registry) {
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public static final class PackageData extends GeneratedMessageLite<PackageData, Builder> implements PackageDataOrBuilder {
        public static final int ACTIVE_CONFIG_AGE_SECONDS_FIELD_NUMBER = 20;
        public static final int ANALYTICS_USER_PROPERTY_FIELD_NUMBER = 17;
        public static final int APP_CERT_HASH_FIELD_NUMBER = 10;
        public static final int APP_INSTANCE_ID_FIELD_NUMBER = 12;
        public static final int APP_INSTANCE_ID_TOKEN_FIELD_NUMBER = 14;
        public static final int APP_VERSION_CODE_FIELD_NUMBER = 11;
        public static final int APP_VERSION_FIELD_NUMBER = 13;
        public static final int CERT_HASH_FIELD_NUMBER = 4;
        public static final int CONFIG_ID_FIELD_NUMBER = 5;
        public static final int CUSTOM_VARIABLE_FIELD_NUMBER = 9;
        private static final PackageData DEFAULT_INSTANCE;
        public static final int DIGEST_FIELD_NUMBER = 3;
        public static final int FETCHED_CONFIG_AGE_SECONDS_FIELD_NUMBER = 19;
        public static final int GAMES_PROJECT_ID_FIELD_NUMBER = 7;
        public static final int GMP_PROJECT_ID_FIELD_NUMBER = 6;
        public static final int NAMESPACE_DIGEST_FIELD_NUMBER = 8;
        public static final int PACKAGE_NAME_FIELD_NUMBER = 1;
        private static volatile Parser<PackageData> PARSER = null;
        public static final int REQUESTED_CACHE_EXPIRATION_SECONDS_FIELD_NUMBER = 18;
        public static final int REQUESTED_HIDDEN_NAMESPACE_FIELD_NUMBER = 15;
        public static final int SDK_VERSION_FIELD_NUMBER = 16;
        public static final int VERSION_CODE_FIELD_NUMBER = 2;
        private int activeConfigAgeSeconds_;
        private int appVersionCode_;
        private int bitField0_;
        private int fetchedConfigAgeSeconds_;
        private int requestedCacheExpirationSeconds_;
        private int sdkVersion_;
        private int versionCode_;
        private ByteString digest_ = ByteString.EMPTY;
        private ByteString certHash_ = ByteString.EMPTY;
        private String configId_ = "";
        private String packageName_ = "";
        private String gmpProjectId_ = "";
        private String gamesProjectId_ = "";
        private Internal.ProtobufList<NamedValue> namespaceDigest_ = emptyProtobufList();
        private Internal.ProtobufList<NamedValue> customVariable_ = emptyProtobufList();
        private ByteString appCertHash_ = ByteString.EMPTY;
        private String appVersion_ = "";
        private String appInstanceId_ = "";
        private String appInstanceIdToken_ = "";
        private Internal.ProtobufList<String> requestedHiddenNamespace_ = GeneratedMessageLite.emptyProtobufList();
        private Internal.ProtobufList<NamedValue> analyticsUserProperty_ = emptyProtobufList();

        private PackageData() {
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public boolean hasVersionCode() {
            return (this.bitField0_ & 1) == 1;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public int getVersionCode() {
            return this.versionCode_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setVersionCode(int value) {
            this.bitField0_ |= 1;
            this.versionCode_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearVersionCode() {
            this.bitField0_ &= -2;
            this.versionCode_ = 0;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public boolean hasDigest() {
            return (this.bitField0_ & 2) == 2;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public ByteString getDigest() {
            return this.digest_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setDigest(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 2;
            this.digest_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearDigest() {
            this.bitField0_ &= -3;
            this.digest_ = getDefaultInstance().getDigest();
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public boolean hasCertHash() {
            return (this.bitField0_ & 4) == 4;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public ByteString getCertHash() {
            return this.certHash_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setCertHash(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 4;
            this.certHash_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearCertHash() {
            this.bitField0_ &= -5;
            this.certHash_ = getDefaultInstance().getCertHash();
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public boolean hasConfigId() {
            return (this.bitField0_ & 8) == 8;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public String getConfigId() {
            return this.configId_;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public ByteString getConfigIdBytes() {
            return ByteString.copyFromUtf8(this.configId_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setConfigId(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 8;
            this.configId_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearConfigId() {
            this.bitField0_ &= -9;
            this.configId_ = getDefaultInstance().getConfigId();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setConfigIdBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 8;
            this.configId_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public boolean hasPackageName() {
            return (this.bitField0_ & 16) == 16;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public String getPackageName() {
            return this.packageName_;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public ByteString getPackageNameBytes() {
            return ByteString.copyFromUtf8(this.packageName_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setPackageName(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 16;
            this.packageName_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearPackageName() {
            this.bitField0_ &= -17;
            this.packageName_ = getDefaultInstance().getPackageName();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setPackageNameBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 16;
            this.packageName_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public boolean hasGmpProjectId() {
            return (this.bitField0_ & 32) == 32;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public String getGmpProjectId() {
            return this.gmpProjectId_;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public ByteString getGmpProjectIdBytes() {
            return ByteString.copyFromUtf8(this.gmpProjectId_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setGmpProjectId(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 32;
            this.gmpProjectId_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearGmpProjectId() {
            this.bitField0_ &= -33;
            this.gmpProjectId_ = getDefaultInstance().getGmpProjectId();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setGmpProjectIdBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 32;
            this.gmpProjectId_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public boolean hasGamesProjectId() {
            return (this.bitField0_ & 64) == 64;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public String getGamesProjectId() {
            return this.gamesProjectId_;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public ByteString getGamesProjectIdBytes() {
            return ByteString.copyFromUtf8(this.gamesProjectId_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setGamesProjectId(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 64;
            this.gamesProjectId_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearGamesProjectId() {
            this.bitField0_ &= -65;
            this.gamesProjectId_ = getDefaultInstance().getGamesProjectId();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setGamesProjectIdBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 64;
            this.gamesProjectId_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public List<NamedValue> getNamespaceDigestList() {
            return this.namespaceDigest_;
        }

        public List<? extends NamedValueOrBuilder> getNamespaceDigestOrBuilderList() {
            return this.namespaceDigest_;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public int getNamespaceDigestCount() {
            return this.namespaceDigest_.size();
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public NamedValue getNamespaceDigest(int index) {
            return this.namespaceDigest_.get(index);
        }

        public NamedValueOrBuilder getNamespaceDigestOrBuilder(int index) {
            return this.namespaceDigest_.get(index);
        }

        private void ensureNamespaceDigestIsMutable() {
            if (!this.namespaceDigest_.isModifiable()) {
                this.namespaceDigest_ = GeneratedMessageLite.mutableCopy(this.namespaceDigest_);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setNamespaceDigest(int index, NamedValue value) {
            if (value == null) {
                throw null;
            }
            ensureNamespaceDigestIsMutable();
            this.namespaceDigest_.set(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setNamespaceDigest(int index, NamedValue.Builder builderForValue) {
            ensureNamespaceDigestIsMutable();
            this.namespaceDigest_.set(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addNamespaceDigest(NamedValue value) {
            if (value == null) {
                throw null;
            }
            ensureNamespaceDigestIsMutable();
            this.namespaceDigest_.add(value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addNamespaceDigest(int index, NamedValue value) {
            if (value == null) {
                throw null;
            }
            ensureNamespaceDigestIsMutable();
            this.namespaceDigest_.add(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addNamespaceDigest(NamedValue.Builder builderForValue) {
            ensureNamespaceDigestIsMutable();
            this.namespaceDigest_.add(builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addNamespaceDigest(int index, NamedValue.Builder builderForValue) {
            ensureNamespaceDigestIsMutable();
            this.namespaceDigest_.add(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAllNamespaceDigest(Iterable<? extends NamedValue> values) {
            ensureNamespaceDigestIsMutable();
            AbstractMessageLite.addAll(values, this.namespaceDigest_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearNamespaceDigest() {
            this.namespaceDigest_ = emptyProtobufList();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void removeNamespaceDigest(int index) {
            ensureNamespaceDigestIsMutable();
            this.namespaceDigest_.remove(index);
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public List<NamedValue> getCustomVariableList() {
            return this.customVariable_;
        }

        public List<? extends NamedValueOrBuilder> getCustomVariableOrBuilderList() {
            return this.customVariable_;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public int getCustomVariableCount() {
            return this.customVariable_.size();
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public NamedValue getCustomVariable(int index) {
            return this.customVariable_.get(index);
        }

        public NamedValueOrBuilder getCustomVariableOrBuilder(int index) {
            return this.customVariable_.get(index);
        }

        private void ensureCustomVariableIsMutable() {
            if (!this.customVariable_.isModifiable()) {
                this.customVariable_ = GeneratedMessageLite.mutableCopy(this.customVariable_);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setCustomVariable(int index, NamedValue value) {
            if (value == null) {
                throw null;
            }
            ensureCustomVariableIsMutable();
            this.customVariable_.set(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setCustomVariable(int index, NamedValue.Builder builderForValue) {
            ensureCustomVariableIsMutable();
            this.customVariable_.set(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addCustomVariable(NamedValue value) {
            if (value == null) {
                throw null;
            }
            ensureCustomVariableIsMutable();
            this.customVariable_.add(value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addCustomVariable(int index, NamedValue value) {
            if (value == null) {
                throw null;
            }
            ensureCustomVariableIsMutable();
            this.customVariable_.add(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addCustomVariable(NamedValue.Builder builderForValue) {
            ensureCustomVariableIsMutable();
            this.customVariable_.add(builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addCustomVariable(int index, NamedValue.Builder builderForValue) {
            ensureCustomVariableIsMutable();
            this.customVariable_.add(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAllCustomVariable(Iterable<? extends NamedValue> values) {
            ensureCustomVariableIsMutable();
            AbstractMessageLite.addAll(values, this.customVariable_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearCustomVariable() {
            this.customVariable_ = emptyProtobufList();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void removeCustomVariable(int index) {
            ensureCustomVariableIsMutable();
            this.customVariable_.remove(index);
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public boolean hasAppCertHash() {
            return (this.bitField0_ & 128) == 128;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public ByteString getAppCertHash() {
            return this.appCertHash_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setAppCertHash(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 128;
            this.appCertHash_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearAppCertHash() {
            this.bitField0_ &= -129;
            this.appCertHash_ = getDefaultInstance().getAppCertHash();
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public boolean hasAppVersionCode() {
            return (this.bitField0_ & 256) == 256;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public int getAppVersionCode() {
            return this.appVersionCode_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setAppVersionCode(int value) {
            this.bitField0_ |= 256;
            this.appVersionCode_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearAppVersionCode() {
            this.bitField0_ &= -257;
            this.appVersionCode_ = 0;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public boolean hasAppVersion() {
            return (this.bitField0_ & 512) == 512;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public String getAppVersion() {
            return this.appVersion_;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public ByteString getAppVersionBytes() {
            return ByteString.copyFromUtf8(this.appVersion_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setAppVersion(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 512;
            this.appVersion_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearAppVersion() {
            this.bitField0_ &= -513;
            this.appVersion_ = getDefaultInstance().getAppVersion();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setAppVersionBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 512;
            this.appVersion_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public boolean hasAppInstanceId() {
            return (this.bitField0_ & 1024) == 1024;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public String getAppInstanceId() {
            return this.appInstanceId_;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public ByteString getAppInstanceIdBytes() {
            return ByteString.copyFromUtf8(this.appInstanceId_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setAppInstanceId(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 1024;
            this.appInstanceId_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearAppInstanceId() {
            this.bitField0_ &= -1025;
            this.appInstanceId_ = getDefaultInstance().getAppInstanceId();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setAppInstanceIdBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 1024;
            this.appInstanceId_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public boolean hasAppInstanceIdToken() {
            return (this.bitField0_ & 2048) == 2048;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public String getAppInstanceIdToken() {
            return this.appInstanceIdToken_;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public ByteString getAppInstanceIdTokenBytes() {
            return ByteString.copyFromUtf8(this.appInstanceIdToken_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setAppInstanceIdToken(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 2048;
            this.appInstanceIdToken_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearAppInstanceIdToken() {
            this.bitField0_ &= -2049;
            this.appInstanceIdToken_ = getDefaultInstance().getAppInstanceIdToken();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setAppInstanceIdTokenBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 2048;
            this.appInstanceIdToken_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public List<String> getRequestedHiddenNamespaceList() {
            return this.requestedHiddenNamespace_;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public int getRequestedHiddenNamespaceCount() {
            return this.requestedHiddenNamespace_.size();
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public String getRequestedHiddenNamespace(int index) {
            return this.requestedHiddenNamespace_.get(index);
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public ByteString getRequestedHiddenNamespaceBytes(int index) {
            return ByteString.copyFromUtf8(this.requestedHiddenNamespace_.get(index));
        }

        private void ensureRequestedHiddenNamespaceIsMutable() {
            if (!this.requestedHiddenNamespace_.isModifiable()) {
                this.requestedHiddenNamespace_ = GeneratedMessageLite.mutableCopy(this.requestedHiddenNamespace_);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setRequestedHiddenNamespace(int index, String value) {
            if (value == null) {
                throw null;
            }
            ensureRequestedHiddenNamespaceIsMutable();
            this.requestedHiddenNamespace_.set(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addRequestedHiddenNamespace(String value) {
            if (value == null) {
                throw null;
            }
            ensureRequestedHiddenNamespaceIsMutable();
            this.requestedHiddenNamespace_.add(value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAllRequestedHiddenNamespace(Iterable<String> values) {
            ensureRequestedHiddenNamespaceIsMutable();
            AbstractMessageLite.addAll(values, this.requestedHiddenNamespace_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearRequestedHiddenNamespace() {
            this.requestedHiddenNamespace_ = GeneratedMessageLite.emptyProtobufList();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addRequestedHiddenNamespaceBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            ensureRequestedHiddenNamespaceIsMutable();
            this.requestedHiddenNamespace_.add(value.toStringUtf8());
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public boolean hasSdkVersion() {
            return (this.bitField0_ & 4096) == 4096;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public int getSdkVersion() {
            return this.sdkVersion_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setSdkVersion(int value) {
            this.bitField0_ |= 4096;
            this.sdkVersion_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearSdkVersion() {
            this.bitField0_ &= -4097;
            this.sdkVersion_ = 0;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public List<NamedValue> getAnalyticsUserPropertyList() {
            return this.analyticsUserProperty_;
        }

        public List<? extends NamedValueOrBuilder> getAnalyticsUserPropertyOrBuilderList() {
            return this.analyticsUserProperty_;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public int getAnalyticsUserPropertyCount() {
            return this.analyticsUserProperty_.size();
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public NamedValue getAnalyticsUserProperty(int index) {
            return this.analyticsUserProperty_.get(index);
        }

        public NamedValueOrBuilder getAnalyticsUserPropertyOrBuilder(int index) {
            return this.analyticsUserProperty_.get(index);
        }

        private void ensureAnalyticsUserPropertyIsMutable() {
            if (!this.analyticsUserProperty_.isModifiable()) {
                this.analyticsUserProperty_ = GeneratedMessageLite.mutableCopy(this.analyticsUserProperty_);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setAnalyticsUserProperty(int index, NamedValue value) {
            if (value == null) {
                throw null;
            }
            ensureAnalyticsUserPropertyIsMutable();
            this.analyticsUserProperty_.set(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setAnalyticsUserProperty(int index, NamedValue.Builder builderForValue) {
            ensureAnalyticsUserPropertyIsMutable();
            this.analyticsUserProperty_.set(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAnalyticsUserProperty(NamedValue value) {
            if (value == null) {
                throw null;
            }
            ensureAnalyticsUserPropertyIsMutable();
            this.analyticsUserProperty_.add(value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAnalyticsUserProperty(int index, NamedValue value) {
            if (value == null) {
                throw null;
            }
            ensureAnalyticsUserPropertyIsMutable();
            this.analyticsUserProperty_.add(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAnalyticsUserProperty(NamedValue.Builder builderForValue) {
            ensureAnalyticsUserPropertyIsMutable();
            this.analyticsUserProperty_.add(builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAnalyticsUserProperty(int index, NamedValue.Builder builderForValue) {
            ensureAnalyticsUserPropertyIsMutable();
            this.analyticsUserProperty_.add(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAllAnalyticsUserProperty(Iterable<? extends NamedValue> values) {
            ensureAnalyticsUserPropertyIsMutable();
            AbstractMessageLite.addAll(values, this.analyticsUserProperty_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearAnalyticsUserProperty() {
            this.analyticsUserProperty_ = emptyProtobufList();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void removeAnalyticsUserProperty(int index) {
            ensureAnalyticsUserPropertyIsMutable();
            this.analyticsUserProperty_.remove(index);
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public boolean hasRequestedCacheExpirationSeconds() {
            return (this.bitField0_ & 8192) == 8192;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public int getRequestedCacheExpirationSeconds() {
            return this.requestedCacheExpirationSeconds_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setRequestedCacheExpirationSeconds(int value) {
            this.bitField0_ |= 8192;
            this.requestedCacheExpirationSeconds_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearRequestedCacheExpirationSeconds() {
            this.bitField0_ &= -8193;
            this.requestedCacheExpirationSeconds_ = 0;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public boolean hasFetchedConfigAgeSeconds() {
            return (this.bitField0_ & 16384) == 16384;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public int getFetchedConfigAgeSeconds() {
            return this.fetchedConfigAgeSeconds_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setFetchedConfigAgeSeconds(int value) {
            this.bitField0_ |= 16384;
            this.fetchedConfigAgeSeconds_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearFetchedConfigAgeSeconds() {
            this.bitField0_ &= -16385;
            this.fetchedConfigAgeSeconds_ = 0;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public boolean hasActiveConfigAgeSeconds() {
            return (this.bitField0_ & 32768) == 32768;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
        public int getActiveConfigAgeSeconds() {
            return this.activeConfigAgeSeconds_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setActiveConfigAgeSeconds(int value) {
            this.bitField0_ |= 32768;
            this.activeConfigAgeSeconds_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearActiveConfigAgeSeconds() {
            this.bitField0_ &= -32769;
            this.activeConfigAgeSeconds_ = 0;
        }

        @Override // com.google.protobuf.MessageLite
        public void writeTo(CodedOutputStream output) throws IOException {
            if ((this.bitField0_ & 16) == 16) {
                output.writeString(1, getPackageName());
            }
            if ((this.bitField0_ & 1) == 1) {
                output.writeInt32(2, this.versionCode_);
            }
            if ((this.bitField0_ & 2) == 2) {
                output.writeBytes(3, this.digest_);
            }
            if ((this.bitField0_ & 4) == 4) {
                output.writeBytes(4, this.certHash_);
            }
            if ((this.bitField0_ & 8) == 8) {
                output.writeString(5, getConfigId());
            }
            if ((this.bitField0_ & 32) == 32) {
                output.writeString(6, getGmpProjectId());
            }
            if ((this.bitField0_ & 64) == 64) {
                output.writeString(7, getGamesProjectId());
            }
            for (int i = 0; i < this.namespaceDigest_.size(); i++) {
                output.writeMessage(8, this.namespaceDigest_.get(i));
            }
            for (int i2 = 0; i2 < this.customVariable_.size(); i2++) {
                output.writeMessage(9, this.customVariable_.get(i2));
            }
            int i3 = this.bitField0_;
            if ((i3 & 128) == 128) {
                output.writeBytes(10, this.appCertHash_);
            }
            if ((this.bitField0_ & 256) == 256) {
                output.writeInt32(11, this.appVersionCode_);
            }
            if ((this.bitField0_ & 1024) == 1024) {
                output.writeString(12, getAppInstanceId());
            }
            if ((this.bitField0_ & 512) == 512) {
                output.writeString(13, getAppVersion());
            }
            if ((this.bitField0_ & 2048) == 2048) {
                output.writeString(14, getAppInstanceIdToken());
            }
            for (int i4 = 0; i4 < this.requestedHiddenNamespace_.size(); i4++) {
                output.writeString(15, this.requestedHiddenNamespace_.get(i4));
            }
            int i5 = this.bitField0_;
            if ((i5 & 4096) == 4096) {
                output.writeInt32(16, this.sdkVersion_);
            }
            for (int i6 = 0; i6 < this.analyticsUserProperty_.size(); i6++) {
                output.writeMessage(17, this.analyticsUserProperty_.get(i6));
            }
            int i7 = this.bitField0_;
            if ((i7 & 8192) == 8192) {
                output.writeInt32(18, this.requestedCacheExpirationSeconds_);
            }
            if ((this.bitField0_ & 16384) == 16384) {
                output.writeInt32(19, this.fetchedConfigAgeSeconds_);
            }
            if ((this.bitField0_ & 32768) == 32768) {
                output.writeInt32(20, this.activeConfigAgeSeconds_);
            }
            this.unknownFields.writeTo(output);
        }

        @Override // com.google.protobuf.MessageLite
        public int getSerializedSize() {
            int size = this.memoizedSerializedSize;
            if (size != -1) {
                return size;
            }
            int size2 = (this.bitField0_ & 16) == 16 ? 0 + CodedOutputStream.computeStringSize(1, getPackageName()) : 0;
            if ((this.bitField0_ & 1) == 1) {
                size2 += CodedOutputStream.computeInt32Size(2, this.versionCode_);
            }
            if ((this.bitField0_ & 2) == 2) {
                size2 += CodedOutputStream.computeBytesSize(3, this.digest_);
            }
            if ((this.bitField0_ & 4) == 4) {
                size2 += CodedOutputStream.computeBytesSize(4, this.certHash_);
            }
            if ((this.bitField0_ & 8) == 8) {
                size2 += CodedOutputStream.computeStringSize(5, getConfigId());
            }
            if ((this.bitField0_ & 32) == 32) {
                size2 += CodedOutputStream.computeStringSize(6, getGmpProjectId());
            }
            if ((this.bitField0_ & 64) == 64) {
                size2 += CodedOutputStream.computeStringSize(7, getGamesProjectId());
            }
            for (int i = 0; i < this.namespaceDigest_.size(); i++) {
                size2 += CodedOutputStream.computeMessageSize(8, this.namespaceDigest_.get(i));
            }
            for (int i2 = 0; i2 < this.customVariable_.size(); i2++) {
                size2 += CodedOutputStream.computeMessageSize(9, this.customVariable_.get(i2));
            }
            int i3 = this.bitField0_;
            if ((i3 & 128) == 128) {
                size2 += CodedOutputStream.computeBytesSize(10, this.appCertHash_);
            }
            if ((this.bitField0_ & 256) == 256) {
                size2 += CodedOutputStream.computeInt32Size(11, this.appVersionCode_);
            }
            if ((this.bitField0_ & 1024) == 1024) {
                size2 += CodedOutputStream.computeStringSize(12, getAppInstanceId());
            }
            if ((this.bitField0_ & 512) == 512) {
                size2 += CodedOutputStream.computeStringSize(13, getAppVersion());
            }
            if ((this.bitField0_ & 2048) == 2048) {
                size2 += CodedOutputStream.computeStringSize(14, getAppInstanceIdToken());
            }
            int dataSize = 0;
            for (int i4 = 0; i4 < this.requestedHiddenNamespace_.size(); i4++) {
                dataSize += CodedOutputStream.computeStringSizeNoTag(this.requestedHiddenNamespace_.get(i4));
            }
            int size3 = size2 + dataSize + (getRequestedHiddenNamespaceList().size() * 1);
            int dataSize2 = this.bitField0_;
            if ((dataSize2 & 4096) == 4096) {
                size3 += CodedOutputStream.computeInt32Size(16, this.sdkVersion_);
            }
            for (int i5 = 0; i5 < this.analyticsUserProperty_.size(); i5++) {
                size3 += CodedOutputStream.computeMessageSize(17, this.analyticsUserProperty_.get(i5));
            }
            int i6 = this.bitField0_;
            if ((i6 & 8192) == 8192) {
                size3 += CodedOutputStream.computeInt32Size(18, this.requestedCacheExpirationSeconds_);
            }
            if ((this.bitField0_ & 16384) == 16384) {
                size3 += CodedOutputStream.computeInt32Size(19, this.fetchedConfigAgeSeconds_);
            }
            if ((this.bitField0_ & 32768) == 32768) {
                size3 += CodedOutputStream.computeInt32Size(20, this.activeConfigAgeSeconds_);
            }
            int size4 = size3 + this.unknownFields.getSerializedSize();
            this.memoizedSerializedSize = size4;
            return size4;
        }

        public static PackageData parseFrom(ByteString data) throws InvalidProtocolBufferException {
            return (PackageData) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static PackageData parseFrom(ByteString data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (PackageData) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static PackageData parseFrom(byte[] data) throws InvalidProtocolBufferException {
            return (PackageData) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static PackageData parseFrom(byte[] data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (PackageData) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static PackageData parseFrom(InputStream input) throws IOException {
            return (PackageData) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static PackageData parseFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (PackageData) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static PackageData parseDelimitedFrom(InputStream input) throws IOException {
            return (PackageData) parseDelimitedFrom(DEFAULT_INSTANCE, input);
        }

        public static PackageData parseDelimitedFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (PackageData) parseDelimitedFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static PackageData parseFrom(CodedInputStream input) throws IOException {
            return (PackageData) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static PackageData parseFrom(CodedInputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (PackageData) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static Builder newBuilder() {
            return DEFAULT_INSTANCE.toBuilder();
        }

        public static Builder newBuilder(PackageData prototype) {
            return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
        }

        /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
        public static final class Builder extends GeneratedMessageLite.Builder<PackageData, Builder> implements PackageDataOrBuilder {
            /* synthetic */ Builder(AnonymousClass1 x0) {
                this();
            }

            private Builder() {
                super(PackageData.DEFAULT_INSTANCE);
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public boolean hasVersionCode() {
                return ((PackageData) this.instance).hasVersionCode();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public int getVersionCode() {
                return ((PackageData) this.instance).getVersionCode();
            }

            public Builder setVersionCode(int value) {
                copyOnWrite();
                ((PackageData) this.instance).setVersionCode(value);
                return this;
            }

            public Builder clearVersionCode() {
                copyOnWrite();
                ((PackageData) this.instance).clearVersionCode();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public boolean hasDigest() {
                return ((PackageData) this.instance).hasDigest();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public ByteString getDigest() {
                return ((PackageData) this.instance).getDigest();
            }

            public Builder setDigest(ByteString value) {
                copyOnWrite();
                ((PackageData) this.instance).setDigest(value);
                return this;
            }

            public Builder clearDigest() {
                copyOnWrite();
                ((PackageData) this.instance).clearDigest();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public boolean hasCertHash() {
                return ((PackageData) this.instance).hasCertHash();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public ByteString getCertHash() {
                return ((PackageData) this.instance).getCertHash();
            }

            public Builder setCertHash(ByteString value) {
                copyOnWrite();
                ((PackageData) this.instance).setCertHash(value);
                return this;
            }

            public Builder clearCertHash() {
                copyOnWrite();
                ((PackageData) this.instance).clearCertHash();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public boolean hasConfigId() {
                return ((PackageData) this.instance).hasConfigId();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public String getConfigId() {
                return ((PackageData) this.instance).getConfigId();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public ByteString getConfigIdBytes() {
                return ((PackageData) this.instance).getConfigIdBytes();
            }

            public Builder setConfigId(String value) {
                copyOnWrite();
                ((PackageData) this.instance).setConfigId(value);
                return this;
            }

            public Builder clearConfigId() {
                copyOnWrite();
                ((PackageData) this.instance).clearConfigId();
                return this;
            }

            public Builder setConfigIdBytes(ByteString value) {
                copyOnWrite();
                ((PackageData) this.instance).setConfigIdBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public boolean hasPackageName() {
                return ((PackageData) this.instance).hasPackageName();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public String getPackageName() {
                return ((PackageData) this.instance).getPackageName();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public ByteString getPackageNameBytes() {
                return ((PackageData) this.instance).getPackageNameBytes();
            }

            public Builder setPackageName(String value) {
                copyOnWrite();
                ((PackageData) this.instance).setPackageName(value);
                return this;
            }

            public Builder clearPackageName() {
                copyOnWrite();
                ((PackageData) this.instance).clearPackageName();
                return this;
            }

            public Builder setPackageNameBytes(ByteString value) {
                copyOnWrite();
                ((PackageData) this.instance).setPackageNameBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public boolean hasGmpProjectId() {
                return ((PackageData) this.instance).hasGmpProjectId();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public String getGmpProjectId() {
                return ((PackageData) this.instance).getGmpProjectId();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public ByteString getGmpProjectIdBytes() {
                return ((PackageData) this.instance).getGmpProjectIdBytes();
            }

            public Builder setGmpProjectId(String value) {
                copyOnWrite();
                ((PackageData) this.instance).setGmpProjectId(value);
                return this;
            }

            public Builder clearGmpProjectId() {
                copyOnWrite();
                ((PackageData) this.instance).clearGmpProjectId();
                return this;
            }

            public Builder setGmpProjectIdBytes(ByteString value) {
                copyOnWrite();
                ((PackageData) this.instance).setGmpProjectIdBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public boolean hasGamesProjectId() {
                return ((PackageData) this.instance).hasGamesProjectId();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public String getGamesProjectId() {
                return ((PackageData) this.instance).getGamesProjectId();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public ByteString getGamesProjectIdBytes() {
                return ((PackageData) this.instance).getGamesProjectIdBytes();
            }

            public Builder setGamesProjectId(String value) {
                copyOnWrite();
                ((PackageData) this.instance).setGamesProjectId(value);
                return this;
            }

            public Builder clearGamesProjectId() {
                copyOnWrite();
                ((PackageData) this.instance).clearGamesProjectId();
                return this;
            }

            public Builder setGamesProjectIdBytes(ByteString value) {
                copyOnWrite();
                ((PackageData) this.instance).setGamesProjectIdBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public List<NamedValue> getNamespaceDigestList() {
                return Collections.unmodifiableList(((PackageData) this.instance).getNamespaceDigestList());
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public int getNamespaceDigestCount() {
                return ((PackageData) this.instance).getNamespaceDigestCount();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public NamedValue getNamespaceDigest(int index) {
                return ((PackageData) this.instance).getNamespaceDigest(index);
            }

            public Builder setNamespaceDigest(int index, NamedValue value) {
                copyOnWrite();
                ((PackageData) this.instance).setNamespaceDigest(index, value);
                return this;
            }

            public Builder setNamespaceDigest(int index, NamedValue.Builder builderForValue) {
                copyOnWrite();
                ((PackageData) this.instance).setNamespaceDigest(index, builderForValue);
                return this;
            }

            public Builder addNamespaceDigest(NamedValue value) {
                copyOnWrite();
                ((PackageData) this.instance).addNamespaceDigest(value);
                return this;
            }

            public Builder addNamespaceDigest(int index, NamedValue value) {
                copyOnWrite();
                ((PackageData) this.instance).addNamespaceDigest(index, value);
                return this;
            }

            public Builder addNamespaceDigest(NamedValue.Builder builderForValue) {
                copyOnWrite();
                ((PackageData) this.instance).addNamespaceDigest(builderForValue);
                return this;
            }

            public Builder addNamespaceDigest(int index, NamedValue.Builder builderForValue) {
                copyOnWrite();
                ((PackageData) this.instance).addNamespaceDigest(index, builderForValue);
                return this;
            }

            public Builder addAllNamespaceDigest(Iterable<? extends NamedValue> values) {
                copyOnWrite();
                ((PackageData) this.instance).addAllNamespaceDigest(values);
                return this;
            }

            public Builder clearNamespaceDigest() {
                copyOnWrite();
                ((PackageData) this.instance).clearNamespaceDigest();
                return this;
            }

            public Builder removeNamespaceDigest(int index) {
                copyOnWrite();
                ((PackageData) this.instance).removeNamespaceDigest(index);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public List<NamedValue> getCustomVariableList() {
                return Collections.unmodifiableList(((PackageData) this.instance).getCustomVariableList());
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public int getCustomVariableCount() {
                return ((PackageData) this.instance).getCustomVariableCount();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public NamedValue getCustomVariable(int index) {
                return ((PackageData) this.instance).getCustomVariable(index);
            }

            public Builder setCustomVariable(int index, NamedValue value) {
                copyOnWrite();
                ((PackageData) this.instance).setCustomVariable(index, value);
                return this;
            }

            public Builder setCustomVariable(int index, NamedValue.Builder builderForValue) {
                copyOnWrite();
                ((PackageData) this.instance).setCustomVariable(index, builderForValue);
                return this;
            }

            public Builder addCustomVariable(NamedValue value) {
                copyOnWrite();
                ((PackageData) this.instance).addCustomVariable(value);
                return this;
            }

            public Builder addCustomVariable(int index, NamedValue value) {
                copyOnWrite();
                ((PackageData) this.instance).addCustomVariable(index, value);
                return this;
            }

            public Builder addCustomVariable(NamedValue.Builder builderForValue) {
                copyOnWrite();
                ((PackageData) this.instance).addCustomVariable(builderForValue);
                return this;
            }

            public Builder addCustomVariable(int index, NamedValue.Builder builderForValue) {
                copyOnWrite();
                ((PackageData) this.instance).addCustomVariable(index, builderForValue);
                return this;
            }

            public Builder addAllCustomVariable(Iterable<? extends NamedValue> values) {
                copyOnWrite();
                ((PackageData) this.instance).addAllCustomVariable(values);
                return this;
            }

            public Builder clearCustomVariable() {
                copyOnWrite();
                ((PackageData) this.instance).clearCustomVariable();
                return this;
            }

            public Builder removeCustomVariable(int index) {
                copyOnWrite();
                ((PackageData) this.instance).removeCustomVariable(index);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public boolean hasAppCertHash() {
                return ((PackageData) this.instance).hasAppCertHash();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public ByteString getAppCertHash() {
                return ((PackageData) this.instance).getAppCertHash();
            }

            public Builder setAppCertHash(ByteString value) {
                copyOnWrite();
                ((PackageData) this.instance).setAppCertHash(value);
                return this;
            }

            public Builder clearAppCertHash() {
                copyOnWrite();
                ((PackageData) this.instance).clearAppCertHash();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public boolean hasAppVersionCode() {
                return ((PackageData) this.instance).hasAppVersionCode();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public int getAppVersionCode() {
                return ((PackageData) this.instance).getAppVersionCode();
            }

            public Builder setAppVersionCode(int value) {
                copyOnWrite();
                ((PackageData) this.instance).setAppVersionCode(value);
                return this;
            }

            public Builder clearAppVersionCode() {
                copyOnWrite();
                ((PackageData) this.instance).clearAppVersionCode();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public boolean hasAppVersion() {
                return ((PackageData) this.instance).hasAppVersion();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public String getAppVersion() {
                return ((PackageData) this.instance).getAppVersion();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public ByteString getAppVersionBytes() {
                return ((PackageData) this.instance).getAppVersionBytes();
            }

            public Builder setAppVersion(String value) {
                copyOnWrite();
                ((PackageData) this.instance).setAppVersion(value);
                return this;
            }

            public Builder clearAppVersion() {
                copyOnWrite();
                ((PackageData) this.instance).clearAppVersion();
                return this;
            }

            public Builder setAppVersionBytes(ByteString value) {
                copyOnWrite();
                ((PackageData) this.instance).setAppVersionBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public boolean hasAppInstanceId() {
                return ((PackageData) this.instance).hasAppInstanceId();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public String getAppInstanceId() {
                return ((PackageData) this.instance).getAppInstanceId();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public ByteString getAppInstanceIdBytes() {
                return ((PackageData) this.instance).getAppInstanceIdBytes();
            }

            public Builder setAppInstanceId(String value) {
                copyOnWrite();
                ((PackageData) this.instance).setAppInstanceId(value);
                return this;
            }

            public Builder clearAppInstanceId() {
                copyOnWrite();
                ((PackageData) this.instance).clearAppInstanceId();
                return this;
            }

            public Builder setAppInstanceIdBytes(ByteString value) {
                copyOnWrite();
                ((PackageData) this.instance).setAppInstanceIdBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public boolean hasAppInstanceIdToken() {
                return ((PackageData) this.instance).hasAppInstanceIdToken();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public String getAppInstanceIdToken() {
                return ((PackageData) this.instance).getAppInstanceIdToken();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public ByteString getAppInstanceIdTokenBytes() {
                return ((PackageData) this.instance).getAppInstanceIdTokenBytes();
            }

            public Builder setAppInstanceIdToken(String value) {
                copyOnWrite();
                ((PackageData) this.instance).setAppInstanceIdToken(value);
                return this;
            }

            public Builder clearAppInstanceIdToken() {
                copyOnWrite();
                ((PackageData) this.instance).clearAppInstanceIdToken();
                return this;
            }

            public Builder setAppInstanceIdTokenBytes(ByteString value) {
                copyOnWrite();
                ((PackageData) this.instance).setAppInstanceIdTokenBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public List<String> getRequestedHiddenNamespaceList() {
                return Collections.unmodifiableList(((PackageData) this.instance).getRequestedHiddenNamespaceList());
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public int getRequestedHiddenNamespaceCount() {
                return ((PackageData) this.instance).getRequestedHiddenNamespaceCount();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public String getRequestedHiddenNamespace(int index) {
                return ((PackageData) this.instance).getRequestedHiddenNamespace(index);
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public ByteString getRequestedHiddenNamespaceBytes(int index) {
                return ((PackageData) this.instance).getRequestedHiddenNamespaceBytes(index);
            }

            public Builder setRequestedHiddenNamespace(int index, String value) {
                copyOnWrite();
                ((PackageData) this.instance).setRequestedHiddenNamespace(index, value);
                return this;
            }

            public Builder addRequestedHiddenNamespace(String value) {
                copyOnWrite();
                ((PackageData) this.instance).addRequestedHiddenNamespace(value);
                return this;
            }

            public Builder addAllRequestedHiddenNamespace(Iterable<String> values) {
                copyOnWrite();
                ((PackageData) this.instance).addAllRequestedHiddenNamespace(values);
                return this;
            }

            public Builder clearRequestedHiddenNamespace() {
                copyOnWrite();
                ((PackageData) this.instance).clearRequestedHiddenNamespace();
                return this;
            }

            public Builder addRequestedHiddenNamespaceBytes(ByteString value) {
                copyOnWrite();
                ((PackageData) this.instance).addRequestedHiddenNamespaceBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public boolean hasSdkVersion() {
                return ((PackageData) this.instance).hasSdkVersion();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public int getSdkVersion() {
                return ((PackageData) this.instance).getSdkVersion();
            }

            public Builder setSdkVersion(int value) {
                copyOnWrite();
                ((PackageData) this.instance).setSdkVersion(value);
                return this;
            }

            public Builder clearSdkVersion() {
                copyOnWrite();
                ((PackageData) this.instance).clearSdkVersion();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public List<NamedValue> getAnalyticsUserPropertyList() {
                return Collections.unmodifiableList(((PackageData) this.instance).getAnalyticsUserPropertyList());
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public int getAnalyticsUserPropertyCount() {
                return ((PackageData) this.instance).getAnalyticsUserPropertyCount();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public NamedValue getAnalyticsUserProperty(int index) {
                return ((PackageData) this.instance).getAnalyticsUserProperty(index);
            }

            public Builder setAnalyticsUserProperty(int index, NamedValue value) {
                copyOnWrite();
                ((PackageData) this.instance).setAnalyticsUserProperty(index, value);
                return this;
            }

            public Builder setAnalyticsUserProperty(int index, NamedValue.Builder builderForValue) {
                copyOnWrite();
                ((PackageData) this.instance).setAnalyticsUserProperty(index, builderForValue);
                return this;
            }

            public Builder addAnalyticsUserProperty(NamedValue value) {
                copyOnWrite();
                ((PackageData) this.instance).addAnalyticsUserProperty(value);
                return this;
            }

            public Builder addAnalyticsUserProperty(int index, NamedValue value) {
                copyOnWrite();
                ((PackageData) this.instance).addAnalyticsUserProperty(index, value);
                return this;
            }

            public Builder addAnalyticsUserProperty(NamedValue.Builder builderForValue) {
                copyOnWrite();
                ((PackageData) this.instance).addAnalyticsUserProperty(builderForValue);
                return this;
            }

            public Builder addAnalyticsUserProperty(int index, NamedValue.Builder builderForValue) {
                copyOnWrite();
                ((PackageData) this.instance).addAnalyticsUserProperty(index, builderForValue);
                return this;
            }

            public Builder addAllAnalyticsUserProperty(Iterable<? extends NamedValue> values) {
                copyOnWrite();
                ((PackageData) this.instance).addAllAnalyticsUserProperty(values);
                return this;
            }

            public Builder clearAnalyticsUserProperty() {
                copyOnWrite();
                ((PackageData) this.instance).clearAnalyticsUserProperty();
                return this;
            }

            public Builder removeAnalyticsUserProperty(int index) {
                copyOnWrite();
                ((PackageData) this.instance).removeAnalyticsUserProperty(index);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public boolean hasRequestedCacheExpirationSeconds() {
                return ((PackageData) this.instance).hasRequestedCacheExpirationSeconds();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public int getRequestedCacheExpirationSeconds() {
                return ((PackageData) this.instance).getRequestedCacheExpirationSeconds();
            }

            public Builder setRequestedCacheExpirationSeconds(int value) {
                copyOnWrite();
                ((PackageData) this.instance).setRequestedCacheExpirationSeconds(value);
                return this;
            }

            public Builder clearRequestedCacheExpirationSeconds() {
                copyOnWrite();
                ((PackageData) this.instance).clearRequestedCacheExpirationSeconds();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public boolean hasFetchedConfigAgeSeconds() {
                return ((PackageData) this.instance).hasFetchedConfigAgeSeconds();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public int getFetchedConfigAgeSeconds() {
                return ((PackageData) this.instance).getFetchedConfigAgeSeconds();
            }

            public Builder setFetchedConfigAgeSeconds(int value) {
                copyOnWrite();
                ((PackageData) this.instance).setFetchedConfigAgeSeconds(value);
                return this;
            }

            public Builder clearFetchedConfigAgeSeconds() {
                copyOnWrite();
                ((PackageData) this.instance).clearFetchedConfigAgeSeconds();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public boolean hasActiveConfigAgeSeconds() {
                return ((PackageData) this.instance).hasActiveConfigAgeSeconds();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageDataOrBuilder
            public int getActiveConfigAgeSeconds() {
                return ((PackageData) this.instance).getActiveConfigAgeSeconds();
            }

            public Builder setActiveConfigAgeSeconds(int value) {
                copyOnWrite();
                ((PackageData) this.instance).setActiveConfigAgeSeconds(value);
                return this;
            }

            public Builder clearActiveConfigAgeSeconds() {
                copyOnWrite();
                ((PackageData) this.instance).clearActiveConfigAgeSeconds();
                return this;
            }
        }

        @Override // com.google.protobuf.GeneratedMessageLite
        protected final Object dynamicMethod(GeneratedMessageLite.MethodToInvoke method, Object arg0, Object arg1) {
            AnonymousClass1 anonymousClass1 = null;
            switch (AnonymousClass1.$SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[method.ordinal()]) {
                case 1:
                    return new PackageData();
                case 2:
                    return DEFAULT_INSTANCE;
                case 3:
                    this.namespaceDigest_.makeImmutable();
                    this.customVariable_.makeImmutable();
                    this.requestedHiddenNamespace_.makeImmutable();
                    this.analyticsUserProperty_.makeImmutable();
                    return null;
                case 4:
                    return new Builder(anonymousClass1);
                case 5:
                    GeneratedMessageLite.Visitor visitor = (GeneratedMessageLite.Visitor) arg0;
                    PackageData other = (PackageData) arg1;
                    this.versionCode_ = visitor.visitInt(hasVersionCode(), this.versionCode_, other.hasVersionCode(), other.versionCode_);
                    this.digest_ = visitor.visitByteString(hasDigest(), this.digest_, other.hasDigest(), other.digest_);
                    this.certHash_ = visitor.visitByteString(hasCertHash(), this.certHash_, other.hasCertHash(), other.certHash_);
                    this.configId_ = visitor.visitString(hasConfigId(), this.configId_, other.hasConfigId(), other.configId_);
                    this.packageName_ = visitor.visitString(hasPackageName(), this.packageName_, other.hasPackageName(), other.packageName_);
                    this.gmpProjectId_ = visitor.visitString(hasGmpProjectId(), this.gmpProjectId_, other.hasGmpProjectId(), other.gmpProjectId_);
                    this.gamesProjectId_ = visitor.visitString(hasGamesProjectId(), this.gamesProjectId_, other.hasGamesProjectId(), other.gamesProjectId_);
                    this.namespaceDigest_ = visitor.visitList(this.namespaceDigest_, other.namespaceDigest_);
                    this.customVariable_ = visitor.visitList(this.customVariable_, other.customVariable_);
                    this.appCertHash_ = visitor.visitByteString(hasAppCertHash(), this.appCertHash_, other.hasAppCertHash(), other.appCertHash_);
                    this.appVersionCode_ = visitor.visitInt(hasAppVersionCode(), this.appVersionCode_, other.hasAppVersionCode(), other.appVersionCode_);
                    this.appVersion_ = visitor.visitString(hasAppVersion(), this.appVersion_, other.hasAppVersion(), other.appVersion_);
                    this.appInstanceId_ = visitor.visitString(hasAppInstanceId(), this.appInstanceId_, other.hasAppInstanceId(), other.appInstanceId_);
                    this.appInstanceIdToken_ = visitor.visitString(hasAppInstanceIdToken(), this.appInstanceIdToken_, other.hasAppInstanceIdToken(), other.appInstanceIdToken_);
                    this.requestedHiddenNamespace_ = visitor.visitList(this.requestedHiddenNamespace_, other.requestedHiddenNamespace_);
                    this.sdkVersion_ = visitor.visitInt(hasSdkVersion(), this.sdkVersion_, other.hasSdkVersion(), other.sdkVersion_);
                    this.analyticsUserProperty_ = visitor.visitList(this.analyticsUserProperty_, other.analyticsUserProperty_);
                    this.requestedCacheExpirationSeconds_ = visitor.visitInt(hasRequestedCacheExpirationSeconds(), this.requestedCacheExpirationSeconds_, other.hasRequestedCacheExpirationSeconds(), other.requestedCacheExpirationSeconds_);
                    this.fetchedConfigAgeSeconds_ = visitor.visitInt(hasFetchedConfigAgeSeconds(), this.fetchedConfigAgeSeconds_, other.hasFetchedConfigAgeSeconds(), other.fetchedConfigAgeSeconds_);
                    this.activeConfigAgeSeconds_ = visitor.visitInt(hasActiveConfigAgeSeconds(), this.activeConfigAgeSeconds_, other.hasActiveConfigAgeSeconds(), other.activeConfigAgeSeconds_);
                    if (visitor == GeneratedMessageLite.MergeFromVisitor.INSTANCE) {
                        this.bitField0_ |= other.bitField0_;
                    }
                    return this;
                case 6:
                    CodedInputStream input = (CodedInputStream) arg0;
                    ExtensionRegistryLite extensionRegistry = (ExtensionRegistryLite) arg1;
                    boolean done = false;
                    while (!done) {
                        try {
                            try {
                                int tag = input.readTag();
                                switch (tag) {
                                    case 0:
                                        done = true;
                                        break;
                                    case 10:
                                        String s = input.readString();
                                        this.bitField0_ |= 16;
                                        this.packageName_ = s;
                                        break;
                                    case 16:
                                        this.bitField0_ |= 1;
                                        this.versionCode_ = input.readInt32();
                                        break;
                                    case 26:
                                        this.bitField0_ |= 2;
                                        this.digest_ = input.readBytes();
                                        break;
                                    case 34:
                                        this.bitField0_ |= 4;
                                        this.certHash_ = input.readBytes();
                                        break;
                                    case 42:
                                        String s2 = input.readString();
                                        this.bitField0_ |= 8;
                                        this.configId_ = s2;
                                        break;
                                    case 50:
                                        String s3 = input.readString();
                                        this.bitField0_ |= 32;
                                        this.gmpProjectId_ = s3;
                                        break;
                                    case 58:
                                        String s4 = input.readString();
                                        this.bitField0_ |= 64;
                                        this.gamesProjectId_ = s4;
                                        break;
                                    case 66:
                                        if (!this.namespaceDigest_.isModifiable()) {
                                            this.namespaceDigest_ = GeneratedMessageLite.mutableCopy(this.namespaceDigest_);
                                        }
                                        this.namespaceDigest_.add((NamedValue) input.readMessage(NamedValue.parser(), extensionRegistry));
                                        break;
                                    case 74:
                                        if (!this.customVariable_.isModifiable()) {
                                            this.customVariable_ = GeneratedMessageLite.mutableCopy(this.customVariable_);
                                        }
                                        this.customVariable_.add((NamedValue) input.readMessage(NamedValue.parser(), extensionRegistry));
                                        break;
                                    case 82:
                                        this.bitField0_ |= 128;
                                        this.appCertHash_ = input.readBytes();
                                        break;
                                    case 88:
                                        this.bitField0_ |= 256;
                                        this.appVersionCode_ = input.readInt32();
                                        break;
                                    case 98:
                                        String s5 = input.readString();
                                        this.bitField0_ |= 1024;
                                        this.appInstanceId_ = s5;
                                        break;
                                    case 106:
                                        String s6 = input.readString();
                                        this.bitField0_ |= 512;
                                        this.appVersion_ = s6;
                                        break;
                                    case 114:
                                        String s7 = input.readString();
                                        this.bitField0_ |= 2048;
                                        this.appInstanceIdToken_ = s7;
                                        break;
                                    case 122:
                                        String s8 = input.readString();
                                        if (!this.requestedHiddenNamespace_.isModifiable()) {
                                            this.requestedHiddenNamespace_ = GeneratedMessageLite.mutableCopy(this.requestedHiddenNamespace_);
                                        }
                                        this.requestedHiddenNamespace_.add(s8);
                                        break;
                                    case 128:
                                        this.bitField0_ |= 4096;
                                        this.sdkVersion_ = input.readInt32();
                                        break;
                                    case TsExtractor.TS_STREAM_TYPE_DTS /* 138 */:
                                        if (!this.analyticsUserProperty_.isModifiable()) {
                                            this.analyticsUserProperty_ = GeneratedMessageLite.mutableCopy(this.analyticsUserProperty_);
                                        }
                                        this.analyticsUserProperty_.add((NamedValue) input.readMessage(NamedValue.parser(), extensionRegistry));
                                        break;
                                    case 144:
                                        this.bitField0_ |= 8192;
                                        this.requestedCacheExpirationSeconds_ = input.readInt32();
                                        break;
                                    case 152:
                                        this.bitField0_ |= 16384;
                                        this.fetchedConfigAgeSeconds_ = input.readInt32();
                                        break;
                                    case 160:
                                        this.bitField0_ |= 32768;
                                        this.activeConfigAgeSeconds_ = input.readInt32();
                                        break;
                                    default:
                                        if (!parseUnknownField(tag, input)) {
                                            done = true;
                                        }
                                        break;
                                }
                            } catch (IOException e) {
                                throw new RuntimeException(new InvalidProtocolBufferException(e.getMessage()).setUnfinishedMessage(this));
                            }
                        } catch (InvalidProtocolBufferException e2) {
                            throw new RuntimeException(e2.setUnfinishedMessage(this));
                        }
                    }
                    break;
                case 7:
                    break;
                case 8:
                    if (PARSER == null) {
                        synchronized (PackageData.class) {
                            if (PARSER == null) {
                                PARSER = new GeneratedMessageLite.DefaultInstanceBasedParser(DEFAULT_INSTANCE);
                            }
                            break;
                        }
                    }
                    return PARSER;
                default:
                    throw new UnsupportedOperationException();
            }
            return DEFAULT_INSTANCE;
        }

        static {
            PackageData packageData = new PackageData();
            DEFAULT_INSTANCE = packageData;
            packageData.makeImmutable();
        }

        public static PackageData getDefaultInstance() {
            return DEFAULT_INSTANCE;
        }

        public static Parser<PackageData> parser() {
            return DEFAULT_INSTANCE.getParserForType();
        }
    }

    /* JADX INFO: renamed from: com.google.android.gms.config.proto.Config$1, reason: invalid class name */
    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke;

        static {
            int[] iArr = new int[GeneratedMessageLite.MethodToInvoke.values().length];
            $SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke = iArr;
            try {
                iArr[GeneratedMessageLite.MethodToInvoke.NEW_MUTABLE_INSTANCE.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[GeneratedMessageLite.MethodToInvoke.IS_INITIALIZED.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[GeneratedMessageLite.MethodToInvoke.MAKE_IMMUTABLE.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[GeneratedMessageLite.MethodToInvoke.NEW_BUILDER.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[GeneratedMessageLite.MethodToInvoke.VISIT.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
            try {
                $SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[GeneratedMessageLite.MethodToInvoke.MERGE_FROM_STREAM.ordinal()] = 6;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[GeneratedMessageLite.MethodToInvoke.GET_DEFAULT_INSTANCE.ordinal()] = 7;
            } catch (NoSuchFieldError e7) {
            }
            try {
                $SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[GeneratedMessageLite.MethodToInvoke.GET_PARSER.ordinal()] = 8;
            } catch (NoSuchFieldError e8) {
            }
        }
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public static final class KeyValue extends GeneratedMessageLite<KeyValue, Builder> implements KeyValueOrBuilder {
        private static final KeyValue DEFAULT_INSTANCE;
        public static final int KEY_FIELD_NUMBER = 1;
        private static volatile Parser<KeyValue> PARSER = null;
        public static final int VALUE_FIELD_NUMBER = 2;
        private int bitField0_;
        private String key_ = "";
        private ByteString value_ = ByteString.EMPTY;

        private KeyValue() {
        }

        @Override // com.google.android.gms.config.proto.Config.KeyValueOrBuilder
        public boolean hasKey() {
            return (this.bitField0_ & 1) == 1;
        }

        @Override // com.google.android.gms.config.proto.Config.KeyValueOrBuilder
        public String getKey() {
            return this.key_;
        }

        @Override // com.google.android.gms.config.proto.Config.KeyValueOrBuilder
        public ByteString getKeyBytes() {
            return ByteString.copyFromUtf8(this.key_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setKey(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 1;
            this.key_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearKey() {
            this.bitField0_ &= -2;
            this.key_ = getDefaultInstance().getKey();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setKeyBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 1;
            this.key_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.KeyValueOrBuilder
        public boolean hasValue() {
            return (this.bitField0_ & 2) == 2;
        }

        @Override // com.google.android.gms.config.proto.Config.KeyValueOrBuilder
        public ByteString getValue() {
            return this.value_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setValue(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 2;
            this.value_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearValue() {
            this.bitField0_ &= -3;
            this.value_ = getDefaultInstance().getValue();
        }

        @Override // com.google.protobuf.MessageLite
        public void writeTo(CodedOutputStream output) throws IOException {
            if ((this.bitField0_ & 1) == 1) {
                output.writeString(1, getKey());
            }
            if ((this.bitField0_ & 2) == 2) {
                output.writeBytes(2, this.value_);
            }
            this.unknownFields.writeTo(output);
        }

        @Override // com.google.protobuf.MessageLite
        public int getSerializedSize() {
            int size = this.memoizedSerializedSize;
            if (size != -1) {
                return size;
            }
            int size2 = (this.bitField0_ & 1) == 1 ? 0 + CodedOutputStream.computeStringSize(1, getKey()) : 0;
            if ((this.bitField0_ & 2) == 2) {
                size2 += CodedOutputStream.computeBytesSize(2, this.value_);
            }
            int size3 = size2 + this.unknownFields.getSerializedSize();
            this.memoizedSerializedSize = size3;
            return size3;
        }

        public static KeyValue parseFrom(ByteString data) throws InvalidProtocolBufferException {
            return (KeyValue) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static KeyValue parseFrom(ByteString data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (KeyValue) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static KeyValue parseFrom(byte[] data) throws InvalidProtocolBufferException {
            return (KeyValue) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static KeyValue parseFrom(byte[] data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (KeyValue) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static KeyValue parseFrom(InputStream input) throws IOException {
            return (KeyValue) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static KeyValue parseFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (KeyValue) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static KeyValue parseDelimitedFrom(InputStream input) throws IOException {
            return (KeyValue) parseDelimitedFrom(DEFAULT_INSTANCE, input);
        }

        public static KeyValue parseDelimitedFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (KeyValue) parseDelimitedFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static KeyValue parseFrom(CodedInputStream input) throws IOException {
            return (KeyValue) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static KeyValue parseFrom(CodedInputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (KeyValue) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static Builder newBuilder() {
            return DEFAULT_INSTANCE.toBuilder();
        }

        public static Builder newBuilder(KeyValue prototype) {
            return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
        }

        /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
        public static final class Builder extends GeneratedMessageLite.Builder<KeyValue, Builder> implements KeyValueOrBuilder {
            /* synthetic */ Builder(AnonymousClass1 x0) {
                this();
            }

            private Builder() {
                super(KeyValue.DEFAULT_INSTANCE);
            }

            @Override // com.google.android.gms.config.proto.Config.KeyValueOrBuilder
            public boolean hasKey() {
                return ((KeyValue) this.instance).hasKey();
            }

            @Override // com.google.android.gms.config.proto.Config.KeyValueOrBuilder
            public String getKey() {
                return ((KeyValue) this.instance).getKey();
            }

            @Override // com.google.android.gms.config.proto.Config.KeyValueOrBuilder
            public ByteString getKeyBytes() {
                return ((KeyValue) this.instance).getKeyBytes();
            }

            public Builder setKey(String value) {
                copyOnWrite();
                ((KeyValue) this.instance).setKey(value);
                return this;
            }

            public Builder clearKey() {
                copyOnWrite();
                ((KeyValue) this.instance).clearKey();
                return this;
            }

            public Builder setKeyBytes(ByteString value) {
                copyOnWrite();
                ((KeyValue) this.instance).setKeyBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.KeyValueOrBuilder
            public boolean hasValue() {
                return ((KeyValue) this.instance).hasValue();
            }

            @Override // com.google.android.gms.config.proto.Config.KeyValueOrBuilder
            public ByteString getValue() {
                return ((KeyValue) this.instance).getValue();
            }

            public Builder setValue(ByteString value) {
                copyOnWrite();
                ((KeyValue) this.instance).setValue(value);
                return this;
            }

            public Builder clearValue() {
                copyOnWrite();
                ((KeyValue) this.instance).clearValue();
                return this;
            }
        }

        @Override // com.google.protobuf.GeneratedMessageLite
        protected final Object dynamicMethod(GeneratedMessageLite.MethodToInvoke method, Object arg0, Object arg1) {
            AnonymousClass1 anonymousClass1 = null;
            switch (AnonymousClass1.$SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[method.ordinal()]) {
                case 1:
                    return new KeyValue();
                case 2:
                    return DEFAULT_INSTANCE;
                case 3:
                    return null;
                case 4:
                    return new Builder(anonymousClass1);
                case 5:
                    GeneratedMessageLite.Visitor visitor = (GeneratedMessageLite.Visitor) arg0;
                    KeyValue other = (KeyValue) arg1;
                    this.key_ = visitor.visitString(hasKey(), this.key_, other.hasKey(), other.key_);
                    this.value_ = visitor.visitByteString(hasValue(), this.value_, other.hasValue(), other.value_);
                    if (visitor == GeneratedMessageLite.MergeFromVisitor.INSTANCE) {
                        this.bitField0_ |= other.bitField0_;
                    }
                    return this;
                case 6:
                    CodedInputStream input = (CodedInputStream) arg0;
                    boolean done = false;
                    while (!done) {
                        try {
                            int tag = input.readTag();
                            if (tag == 0) {
                                done = true;
                            } else if (tag == 10) {
                                String s = input.readString();
                                this.bitField0_ |= 1;
                                this.key_ = s;
                            } else if (tag != 18) {
                                if (!parseUnknownField(tag, input)) {
                                    done = true;
                                }
                            } else {
                                this.bitField0_ |= 2;
                                this.value_ = input.readBytes();
                            }
                        } catch (InvalidProtocolBufferException e) {
                            throw new RuntimeException(e.setUnfinishedMessage(this));
                        } catch (IOException e2) {
                            throw new RuntimeException(new InvalidProtocolBufferException(e2.getMessage()).setUnfinishedMessage(this));
                        }
                    }
                    break;
                case 7:
                    break;
                case 8:
                    if (PARSER == null) {
                        synchronized (KeyValue.class) {
                            if (PARSER == null) {
                                PARSER = new GeneratedMessageLite.DefaultInstanceBasedParser(DEFAULT_INSTANCE);
                            }
                            break;
                        }
                    }
                    return PARSER;
                default:
                    throw new UnsupportedOperationException();
            }
            return DEFAULT_INSTANCE;
        }

        static {
            KeyValue keyValue = new KeyValue();
            DEFAULT_INSTANCE = keyValue;
            keyValue.makeImmutable();
        }

        public static KeyValue getDefaultInstance() {
            return DEFAULT_INSTANCE;
        }

        public static Parser<KeyValue> parser() {
            return DEFAULT_INSTANCE.getParserForType();
        }
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public static final class NamedValue extends GeneratedMessageLite<NamedValue, Builder> implements NamedValueOrBuilder {
        private static final NamedValue DEFAULT_INSTANCE;
        public static final int NAME_FIELD_NUMBER = 1;
        private static volatile Parser<NamedValue> PARSER = null;
        public static final int VALUE_FIELD_NUMBER = 2;
        private int bitField0_;
        private String name_ = "";
        private String value_ = "";

        private NamedValue() {
        }

        @Override // com.google.android.gms.config.proto.Config.NamedValueOrBuilder
        public boolean hasName() {
            return (this.bitField0_ & 1) == 1;
        }

        @Override // com.google.android.gms.config.proto.Config.NamedValueOrBuilder
        public String getName() {
            return this.name_;
        }

        @Override // com.google.android.gms.config.proto.Config.NamedValueOrBuilder
        public ByteString getNameBytes() {
            return ByteString.copyFromUtf8(this.name_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setName(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 1;
            this.name_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearName() {
            this.bitField0_ &= -2;
            this.name_ = getDefaultInstance().getName();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setNameBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 1;
            this.name_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.NamedValueOrBuilder
        public boolean hasValue() {
            return (this.bitField0_ & 2) == 2;
        }

        @Override // com.google.android.gms.config.proto.Config.NamedValueOrBuilder
        public String getValue() {
            return this.value_;
        }

        @Override // com.google.android.gms.config.proto.Config.NamedValueOrBuilder
        public ByteString getValueBytes() {
            return ByteString.copyFromUtf8(this.value_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setValue(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 2;
            this.value_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearValue() {
            this.bitField0_ &= -3;
            this.value_ = getDefaultInstance().getValue();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setValueBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 2;
            this.value_ = value.toStringUtf8();
        }

        @Override // com.google.protobuf.MessageLite
        public void writeTo(CodedOutputStream output) throws IOException {
            if ((this.bitField0_ & 1) == 1) {
                output.writeString(1, getName());
            }
            if ((this.bitField0_ & 2) == 2) {
                output.writeString(2, getValue());
            }
            this.unknownFields.writeTo(output);
        }

        @Override // com.google.protobuf.MessageLite
        public int getSerializedSize() {
            int size = this.memoizedSerializedSize;
            if (size != -1) {
                return size;
            }
            int size2 = (this.bitField0_ & 1) == 1 ? 0 + CodedOutputStream.computeStringSize(1, getName()) : 0;
            if ((this.bitField0_ & 2) == 2) {
                size2 += CodedOutputStream.computeStringSize(2, getValue());
            }
            int size3 = size2 + this.unknownFields.getSerializedSize();
            this.memoizedSerializedSize = size3;
            return size3;
        }

        public static NamedValue parseFrom(ByteString data) throws InvalidProtocolBufferException {
            return (NamedValue) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static NamedValue parseFrom(ByteString data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (NamedValue) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static NamedValue parseFrom(byte[] data) throws InvalidProtocolBufferException {
            return (NamedValue) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static NamedValue parseFrom(byte[] data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (NamedValue) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static NamedValue parseFrom(InputStream input) throws IOException {
            return (NamedValue) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static NamedValue parseFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (NamedValue) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static NamedValue parseDelimitedFrom(InputStream input) throws IOException {
            return (NamedValue) parseDelimitedFrom(DEFAULT_INSTANCE, input);
        }

        public static NamedValue parseDelimitedFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (NamedValue) parseDelimitedFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static NamedValue parseFrom(CodedInputStream input) throws IOException {
            return (NamedValue) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static NamedValue parseFrom(CodedInputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (NamedValue) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static Builder newBuilder() {
            return DEFAULT_INSTANCE.toBuilder();
        }

        public static Builder newBuilder(NamedValue prototype) {
            return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
        }

        /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
        public static final class Builder extends GeneratedMessageLite.Builder<NamedValue, Builder> implements NamedValueOrBuilder {
            /* synthetic */ Builder(AnonymousClass1 x0) {
                this();
            }

            private Builder() {
                super(NamedValue.DEFAULT_INSTANCE);
            }

            @Override // com.google.android.gms.config.proto.Config.NamedValueOrBuilder
            public boolean hasName() {
                return ((NamedValue) this.instance).hasName();
            }

            @Override // com.google.android.gms.config.proto.Config.NamedValueOrBuilder
            public String getName() {
                return ((NamedValue) this.instance).getName();
            }

            @Override // com.google.android.gms.config.proto.Config.NamedValueOrBuilder
            public ByteString getNameBytes() {
                return ((NamedValue) this.instance).getNameBytes();
            }

            public Builder setName(String value) {
                copyOnWrite();
                ((NamedValue) this.instance).setName(value);
                return this;
            }

            public Builder clearName() {
                copyOnWrite();
                ((NamedValue) this.instance).clearName();
                return this;
            }

            public Builder setNameBytes(ByteString value) {
                copyOnWrite();
                ((NamedValue) this.instance).setNameBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.NamedValueOrBuilder
            public boolean hasValue() {
                return ((NamedValue) this.instance).hasValue();
            }

            @Override // com.google.android.gms.config.proto.Config.NamedValueOrBuilder
            public String getValue() {
                return ((NamedValue) this.instance).getValue();
            }

            @Override // com.google.android.gms.config.proto.Config.NamedValueOrBuilder
            public ByteString getValueBytes() {
                return ((NamedValue) this.instance).getValueBytes();
            }

            public Builder setValue(String value) {
                copyOnWrite();
                ((NamedValue) this.instance).setValue(value);
                return this;
            }

            public Builder clearValue() {
                copyOnWrite();
                ((NamedValue) this.instance).clearValue();
                return this;
            }

            public Builder setValueBytes(ByteString value) {
                copyOnWrite();
                ((NamedValue) this.instance).setValueBytes(value);
                return this;
            }
        }

        @Override // com.google.protobuf.GeneratedMessageLite
        protected final Object dynamicMethod(GeneratedMessageLite.MethodToInvoke method, Object arg0, Object arg1) {
            AnonymousClass1 anonymousClass1 = null;
            switch (AnonymousClass1.$SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[method.ordinal()]) {
                case 1:
                    return new NamedValue();
                case 2:
                    return DEFAULT_INSTANCE;
                case 3:
                    return null;
                case 4:
                    return new Builder(anonymousClass1);
                case 5:
                    GeneratedMessageLite.Visitor visitor = (GeneratedMessageLite.Visitor) arg0;
                    NamedValue other = (NamedValue) arg1;
                    this.name_ = visitor.visitString(hasName(), this.name_, other.hasName(), other.name_);
                    this.value_ = visitor.visitString(hasValue(), this.value_, other.hasValue(), other.value_);
                    if (visitor == GeneratedMessageLite.MergeFromVisitor.INSTANCE) {
                        this.bitField0_ |= other.bitField0_;
                    }
                    return this;
                case 6:
                    CodedInputStream input = (CodedInputStream) arg0;
                    boolean done = false;
                    while (!done) {
                        try {
                            int tag = input.readTag();
                            if (tag == 0) {
                                done = true;
                            } else if (tag == 10) {
                                String s = input.readString();
                                this.bitField0_ |= 1;
                                this.name_ = s;
                            } else if (tag != 18) {
                                if (!parseUnknownField(tag, input)) {
                                    done = true;
                                }
                            } else {
                                String s2 = input.readString();
                                this.bitField0_ |= 2;
                                this.value_ = s2;
                            }
                        } catch (InvalidProtocolBufferException e) {
                            throw new RuntimeException(e.setUnfinishedMessage(this));
                        } catch (IOException e2) {
                            throw new RuntimeException(new InvalidProtocolBufferException(e2.getMessage()).setUnfinishedMessage(this));
                        }
                    }
                    break;
                case 7:
                    break;
                case 8:
                    if (PARSER == null) {
                        synchronized (NamedValue.class) {
                            if (PARSER == null) {
                                PARSER = new GeneratedMessageLite.DefaultInstanceBasedParser(DEFAULT_INSTANCE);
                            }
                            break;
                        }
                    }
                    return PARSER;
                default:
                    throw new UnsupportedOperationException();
            }
            return DEFAULT_INSTANCE;
        }

        static {
            NamedValue namedValue = new NamedValue();
            DEFAULT_INSTANCE = namedValue;
            namedValue.makeImmutable();
        }

        public static NamedValue getDefaultInstance() {
            return DEFAULT_INSTANCE;
        }

        public static Parser<NamedValue> parser() {
            return DEFAULT_INSTANCE.getParserForType();
        }
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public static final class ConfigFetchRequest extends GeneratedMessageLite<ConfigFetchRequest, Builder> implements ConfigFetchRequestOrBuilder {
        public static final int ANDROID_ID_FIELD_NUMBER = 1;
        public static final int API_LEVEL_FIELD_NUMBER = 8;
        public static final int CLIENT_VERSION_FIELD_NUMBER = 6;
        public static final int CONFIG_FIELD_NUMBER = 5;
        private static final ConfigFetchRequest DEFAULT_INSTANCE;
        public static final int DEVICE_COUNTRY_FIELD_NUMBER = 9;
        public static final int DEVICE_DATA_VERSION_INFO_FIELD_NUMBER = 3;
        public static final int DEVICE_LOCALE_FIELD_NUMBER = 10;
        public static final int DEVICE_SUBTYPE_FIELD_NUMBER = 12;
        public static final int DEVICE_TIMEZONE_ID_FIELD_NUMBER = 14;
        public static final int DEVICE_TYPE_FIELD_NUMBER = 11;
        public static final int GMS_CORE_VERSION_FIELD_NUMBER = 7;
        public static final int OS_VERSION_FIELD_NUMBER = 13;
        public static final int PACKAGE_DATA_FIELD_NUMBER = 2;
        private static volatile Parser<ConfigFetchRequest> PARSER = null;
        public static final int SECURITY_TOKEN_FIELD_NUMBER = 4;
        private long androidId_;
        private int apiLevel_;
        private int bitField0_;
        private int clientVersion_;
        private Logs.AndroidConfigFetchProto config_;
        private int deviceSubtype_;
        private int deviceType_;
        private int gmsCoreVersion_;
        private long securityToken_;
        private Internal.ProtobufList<PackageData> packageData_ = emptyProtobufList();
        private String deviceDataVersionInfo_ = "";
        private String deviceCountry_ = "";
        private String deviceLocale_ = "";
        private String osVersion_ = "";
        private String deviceTimezoneId_ = "";

        private ConfigFetchRequest() {
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public boolean hasConfig() {
            return (this.bitField0_ & 1) == 1;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public Logs.AndroidConfigFetchProto getConfig() {
            Logs.AndroidConfigFetchProto androidConfigFetchProto = this.config_;
            return androidConfigFetchProto == null ? Logs.AndroidConfigFetchProto.getDefaultInstance() : androidConfigFetchProto;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setConfig(Logs.AndroidConfigFetchProto value) {
            if (value == null) {
                throw null;
            }
            this.config_ = value;
            this.bitField0_ |= 1;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setConfig(Logs.AndroidConfigFetchProto.Builder builderForValue) {
            this.config_ = builderForValue.build();
            this.bitField0_ |= 1;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void mergeConfig(Logs.AndroidConfigFetchProto value) {
            Logs.AndroidConfigFetchProto androidConfigFetchProto = this.config_;
            if (androidConfigFetchProto != null && androidConfigFetchProto != Logs.AndroidConfigFetchProto.getDefaultInstance()) {
                this.config_ = Logs.AndroidConfigFetchProto.newBuilder(this.config_).mergeFrom(value).buildPartial();
            } else {
                this.config_ = value;
            }
            this.bitField0_ |= 1;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearConfig() {
            this.config_ = null;
            this.bitField0_ &= -2;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public boolean hasAndroidId() {
            return (this.bitField0_ & 2) == 2;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public long getAndroidId() {
            return this.androidId_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setAndroidId(long value) {
            this.bitField0_ |= 2;
            this.androidId_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearAndroidId() {
            this.bitField0_ &= -3;
            this.androidId_ = 0L;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public List<PackageData> getPackageDataList() {
            return this.packageData_;
        }

        public List<? extends PackageDataOrBuilder> getPackageDataOrBuilderList() {
            return this.packageData_;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public int getPackageDataCount() {
            return this.packageData_.size();
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public PackageData getPackageData(int index) {
            return this.packageData_.get(index);
        }

        public PackageDataOrBuilder getPackageDataOrBuilder(int index) {
            return this.packageData_.get(index);
        }

        private void ensurePackageDataIsMutable() {
            if (!this.packageData_.isModifiable()) {
                this.packageData_ = GeneratedMessageLite.mutableCopy(this.packageData_);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setPackageData(int index, PackageData value) {
            if (value == null) {
                throw null;
            }
            ensurePackageDataIsMutable();
            this.packageData_.set(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setPackageData(int index, PackageData.Builder builderForValue) {
            ensurePackageDataIsMutable();
            this.packageData_.set(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addPackageData(PackageData value) {
            if (value == null) {
                throw null;
            }
            ensurePackageDataIsMutable();
            this.packageData_.add(value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addPackageData(int index, PackageData value) {
            if (value == null) {
                throw null;
            }
            ensurePackageDataIsMutable();
            this.packageData_.add(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addPackageData(PackageData.Builder builderForValue) {
            ensurePackageDataIsMutable();
            this.packageData_.add(builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addPackageData(int index, PackageData.Builder builderForValue) {
            ensurePackageDataIsMutable();
            this.packageData_.add(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAllPackageData(Iterable<? extends PackageData> values) {
            ensurePackageDataIsMutable();
            AbstractMessageLite.addAll(values, this.packageData_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearPackageData() {
            this.packageData_ = emptyProtobufList();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void removePackageData(int index) {
            ensurePackageDataIsMutable();
            this.packageData_.remove(index);
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public boolean hasDeviceDataVersionInfo() {
            return (this.bitField0_ & 4) == 4;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public String getDeviceDataVersionInfo() {
            return this.deviceDataVersionInfo_;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public ByteString getDeviceDataVersionInfoBytes() {
            return ByteString.copyFromUtf8(this.deviceDataVersionInfo_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setDeviceDataVersionInfo(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 4;
            this.deviceDataVersionInfo_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearDeviceDataVersionInfo() {
            this.bitField0_ &= -5;
            this.deviceDataVersionInfo_ = getDefaultInstance().getDeviceDataVersionInfo();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setDeviceDataVersionInfoBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 4;
            this.deviceDataVersionInfo_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public boolean hasSecurityToken() {
            return (this.bitField0_ & 8) == 8;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public long getSecurityToken() {
            return this.securityToken_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setSecurityToken(long value) {
            this.bitField0_ |= 8;
            this.securityToken_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearSecurityToken() {
            this.bitField0_ &= -9;
            this.securityToken_ = 0L;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public boolean hasClientVersion() {
            return (this.bitField0_ & 16) == 16;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public int getClientVersion() {
            return this.clientVersion_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setClientVersion(int value) {
            this.bitField0_ |= 16;
            this.clientVersion_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearClientVersion() {
            this.bitField0_ &= -17;
            this.clientVersion_ = 0;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public boolean hasGmsCoreVersion() {
            return (this.bitField0_ & 32) == 32;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public int getGmsCoreVersion() {
            return this.gmsCoreVersion_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setGmsCoreVersion(int value) {
            this.bitField0_ |= 32;
            this.gmsCoreVersion_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearGmsCoreVersion() {
            this.bitField0_ &= -33;
            this.gmsCoreVersion_ = 0;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public boolean hasApiLevel() {
            return (this.bitField0_ & 64) == 64;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public int getApiLevel() {
            return this.apiLevel_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setApiLevel(int value) {
            this.bitField0_ |= 64;
            this.apiLevel_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearApiLevel() {
            this.bitField0_ &= -65;
            this.apiLevel_ = 0;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public boolean hasDeviceCountry() {
            return (this.bitField0_ & 128) == 128;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public String getDeviceCountry() {
            return this.deviceCountry_;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public ByteString getDeviceCountryBytes() {
            return ByteString.copyFromUtf8(this.deviceCountry_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setDeviceCountry(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 128;
            this.deviceCountry_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearDeviceCountry() {
            this.bitField0_ &= -129;
            this.deviceCountry_ = getDefaultInstance().getDeviceCountry();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setDeviceCountryBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 128;
            this.deviceCountry_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public boolean hasDeviceLocale() {
            return (this.bitField0_ & 256) == 256;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public String getDeviceLocale() {
            return this.deviceLocale_;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public ByteString getDeviceLocaleBytes() {
            return ByteString.copyFromUtf8(this.deviceLocale_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setDeviceLocale(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 256;
            this.deviceLocale_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearDeviceLocale() {
            this.bitField0_ &= -257;
            this.deviceLocale_ = getDefaultInstance().getDeviceLocale();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setDeviceLocaleBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 256;
            this.deviceLocale_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public boolean hasDeviceType() {
            return (this.bitField0_ & 512) == 512;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public int getDeviceType() {
            return this.deviceType_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setDeviceType(int value) {
            this.bitField0_ |= 512;
            this.deviceType_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearDeviceType() {
            this.bitField0_ &= -513;
            this.deviceType_ = 0;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public boolean hasDeviceSubtype() {
            return (this.bitField0_ & 1024) == 1024;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public int getDeviceSubtype() {
            return this.deviceSubtype_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setDeviceSubtype(int value) {
            this.bitField0_ |= 1024;
            this.deviceSubtype_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearDeviceSubtype() {
            this.bitField0_ &= -1025;
            this.deviceSubtype_ = 0;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public boolean hasOsVersion() {
            return (this.bitField0_ & 2048) == 2048;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public String getOsVersion() {
            return this.osVersion_;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public ByteString getOsVersionBytes() {
            return ByteString.copyFromUtf8(this.osVersion_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setOsVersion(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 2048;
            this.osVersion_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearOsVersion() {
            this.bitField0_ &= -2049;
            this.osVersion_ = getDefaultInstance().getOsVersion();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setOsVersionBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 2048;
            this.osVersion_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public boolean hasDeviceTimezoneId() {
            return (this.bitField0_ & 4096) == 4096;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public String getDeviceTimezoneId() {
            return this.deviceTimezoneId_;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
        public ByteString getDeviceTimezoneIdBytes() {
            return ByteString.copyFromUtf8(this.deviceTimezoneId_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setDeviceTimezoneId(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 4096;
            this.deviceTimezoneId_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearDeviceTimezoneId() {
            this.bitField0_ &= -4097;
            this.deviceTimezoneId_ = getDefaultInstance().getDeviceTimezoneId();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setDeviceTimezoneIdBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 4096;
            this.deviceTimezoneId_ = value.toStringUtf8();
        }

        @Override // com.google.protobuf.MessageLite
        public void writeTo(CodedOutputStream output) throws IOException {
            if ((this.bitField0_ & 2) == 2) {
                output.writeFixed64(1, this.androidId_);
            }
            for (int i = 0; i < this.packageData_.size(); i++) {
                output.writeMessage(2, this.packageData_.get(i));
            }
            int i2 = this.bitField0_;
            if ((i2 & 4) == 4) {
                output.writeString(3, getDeviceDataVersionInfo());
            }
            if ((this.bitField0_ & 8) == 8) {
                output.writeFixed64(4, this.securityToken_);
            }
            if ((this.bitField0_ & 1) == 1) {
                output.writeMessage(5, getConfig());
            }
            if ((this.bitField0_ & 16) == 16) {
                output.writeInt32(6, this.clientVersion_);
            }
            if ((this.bitField0_ & 32) == 32) {
                output.writeInt32(7, this.gmsCoreVersion_);
            }
            if ((this.bitField0_ & 64) == 64) {
                output.writeInt32(8, this.apiLevel_);
            }
            if ((this.bitField0_ & 128) == 128) {
                output.writeString(9, getDeviceCountry());
            }
            if ((this.bitField0_ & 256) == 256) {
                output.writeString(10, getDeviceLocale());
            }
            if ((this.bitField0_ & 512) == 512) {
                output.writeInt32(11, this.deviceType_);
            }
            if ((this.bitField0_ & 1024) == 1024) {
                output.writeInt32(12, this.deviceSubtype_);
            }
            if ((this.bitField0_ & 2048) == 2048) {
                output.writeString(13, getOsVersion());
            }
            if ((this.bitField0_ & 4096) == 4096) {
                output.writeString(14, getDeviceTimezoneId());
            }
            this.unknownFields.writeTo(output);
        }

        @Override // com.google.protobuf.MessageLite
        public int getSerializedSize() {
            int size = this.memoizedSerializedSize;
            if (size != -1) {
                return size;
            }
            int size2 = (this.bitField0_ & 2) == 2 ? 0 + CodedOutputStream.computeFixed64Size(1, this.androidId_) : 0;
            for (int i = 0; i < this.packageData_.size(); i++) {
                size2 += CodedOutputStream.computeMessageSize(2, this.packageData_.get(i));
            }
            int i2 = this.bitField0_;
            if ((i2 & 4) == 4) {
                size2 += CodedOutputStream.computeStringSize(3, getDeviceDataVersionInfo());
            }
            if ((this.bitField0_ & 8) == 8) {
                size2 += CodedOutputStream.computeFixed64Size(4, this.securityToken_);
            }
            if ((this.bitField0_ & 1) == 1) {
                size2 += CodedOutputStream.computeMessageSize(5, getConfig());
            }
            if ((this.bitField0_ & 16) == 16) {
                size2 += CodedOutputStream.computeInt32Size(6, this.clientVersion_);
            }
            if ((this.bitField0_ & 32) == 32) {
                size2 += CodedOutputStream.computeInt32Size(7, this.gmsCoreVersion_);
            }
            if ((this.bitField0_ & 64) == 64) {
                size2 += CodedOutputStream.computeInt32Size(8, this.apiLevel_);
            }
            if ((this.bitField0_ & 128) == 128) {
                size2 += CodedOutputStream.computeStringSize(9, getDeviceCountry());
            }
            if ((this.bitField0_ & 256) == 256) {
                size2 += CodedOutputStream.computeStringSize(10, getDeviceLocale());
            }
            if ((this.bitField0_ & 512) == 512) {
                size2 += CodedOutputStream.computeInt32Size(11, this.deviceType_);
            }
            if ((this.bitField0_ & 1024) == 1024) {
                size2 += CodedOutputStream.computeInt32Size(12, this.deviceSubtype_);
            }
            if ((this.bitField0_ & 2048) == 2048) {
                size2 += CodedOutputStream.computeStringSize(13, getOsVersion());
            }
            if ((this.bitField0_ & 4096) == 4096) {
                size2 += CodedOutputStream.computeStringSize(14, getDeviceTimezoneId());
            }
            int size3 = size2 + this.unknownFields.getSerializedSize();
            this.memoizedSerializedSize = size3;
            return size3;
        }

        public static ConfigFetchRequest parseFrom(ByteString data) throws InvalidProtocolBufferException {
            return (ConfigFetchRequest) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static ConfigFetchRequest parseFrom(ByteString data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (ConfigFetchRequest) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static ConfigFetchRequest parseFrom(byte[] data) throws InvalidProtocolBufferException {
            return (ConfigFetchRequest) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static ConfigFetchRequest parseFrom(byte[] data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (ConfigFetchRequest) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static ConfigFetchRequest parseFrom(InputStream input) throws IOException {
            return (ConfigFetchRequest) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static ConfigFetchRequest parseFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (ConfigFetchRequest) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static ConfigFetchRequest parseDelimitedFrom(InputStream input) throws IOException {
            return (ConfigFetchRequest) parseDelimitedFrom(DEFAULT_INSTANCE, input);
        }

        public static ConfigFetchRequest parseDelimitedFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (ConfigFetchRequest) parseDelimitedFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static ConfigFetchRequest parseFrom(CodedInputStream input) throws IOException {
            return (ConfigFetchRequest) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static ConfigFetchRequest parseFrom(CodedInputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (ConfigFetchRequest) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static Builder newBuilder() {
            return DEFAULT_INSTANCE.toBuilder();
        }

        public static Builder newBuilder(ConfigFetchRequest prototype) {
            return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
        }

        /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
        public static final class Builder extends GeneratedMessageLite.Builder<ConfigFetchRequest, Builder> implements ConfigFetchRequestOrBuilder {
            /* synthetic */ Builder(AnonymousClass1 x0) {
                this();
            }

            private Builder() {
                super(ConfigFetchRequest.DEFAULT_INSTANCE);
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public boolean hasConfig() {
                return ((ConfigFetchRequest) this.instance).hasConfig();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public Logs.AndroidConfigFetchProto getConfig() {
                return ((ConfigFetchRequest) this.instance).getConfig();
            }

            public Builder setConfig(Logs.AndroidConfigFetchProto value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setConfig(value);
                return this;
            }

            public Builder setConfig(Logs.AndroidConfigFetchProto.Builder builderForValue) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setConfig(builderForValue);
                return this;
            }

            public Builder mergeConfig(Logs.AndroidConfigFetchProto value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).mergeConfig(value);
                return this;
            }

            public Builder clearConfig() {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).clearConfig();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public boolean hasAndroidId() {
                return ((ConfigFetchRequest) this.instance).hasAndroidId();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public long getAndroidId() {
                return ((ConfigFetchRequest) this.instance).getAndroidId();
            }

            public Builder setAndroidId(long value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setAndroidId(value);
                return this;
            }

            public Builder clearAndroidId() {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).clearAndroidId();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public List<PackageData> getPackageDataList() {
                return Collections.unmodifiableList(((ConfigFetchRequest) this.instance).getPackageDataList());
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public int getPackageDataCount() {
                return ((ConfigFetchRequest) this.instance).getPackageDataCount();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public PackageData getPackageData(int index) {
                return ((ConfigFetchRequest) this.instance).getPackageData(index);
            }

            public Builder setPackageData(int index, PackageData value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setPackageData(index, value);
                return this;
            }

            public Builder setPackageData(int index, PackageData.Builder builderForValue) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setPackageData(index, builderForValue);
                return this;
            }

            public Builder addPackageData(PackageData value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).addPackageData(value);
                return this;
            }

            public Builder addPackageData(int index, PackageData value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).addPackageData(index, value);
                return this;
            }

            public Builder addPackageData(PackageData.Builder builderForValue) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).addPackageData(builderForValue);
                return this;
            }

            public Builder addPackageData(int index, PackageData.Builder builderForValue) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).addPackageData(index, builderForValue);
                return this;
            }

            public Builder addAllPackageData(Iterable<? extends PackageData> values) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).addAllPackageData(values);
                return this;
            }

            public Builder clearPackageData() {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).clearPackageData();
                return this;
            }

            public Builder removePackageData(int index) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).removePackageData(index);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public boolean hasDeviceDataVersionInfo() {
                return ((ConfigFetchRequest) this.instance).hasDeviceDataVersionInfo();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public String getDeviceDataVersionInfo() {
                return ((ConfigFetchRequest) this.instance).getDeviceDataVersionInfo();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public ByteString getDeviceDataVersionInfoBytes() {
                return ((ConfigFetchRequest) this.instance).getDeviceDataVersionInfoBytes();
            }

            public Builder setDeviceDataVersionInfo(String value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setDeviceDataVersionInfo(value);
                return this;
            }

            public Builder clearDeviceDataVersionInfo() {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).clearDeviceDataVersionInfo();
                return this;
            }

            public Builder setDeviceDataVersionInfoBytes(ByteString value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setDeviceDataVersionInfoBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public boolean hasSecurityToken() {
                return ((ConfigFetchRequest) this.instance).hasSecurityToken();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public long getSecurityToken() {
                return ((ConfigFetchRequest) this.instance).getSecurityToken();
            }

            public Builder setSecurityToken(long value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setSecurityToken(value);
                return this;
            }

            public Builder clearSecurityToken() {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).clearSecurityToken();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public boolean hasClientVersion() {
                return ((ConfigFetchRequest) this.instance).hasClientVersion();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public int getClientVersion() {
                return ((ConfigFetchRequest) this.instance).getClientVersion();
            }

            public Builder setClientVersion(int value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setClientVersion(value);
                return this;
            }

            public Builder clearClientVersion() {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).clearClientVersion();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public boolean hasGmsCoreVersion() {
                return ((ConfigFetchRequest) this.instance).hasGmsCoreVersion();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public int getGmsCoreVersion() {
                return ((ConfigFetchRequest) this.instance).getGmsCoreVersion();
            }

            public Builder setGmsCoreVersion(int value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setGmsCoreVersion(value);
                return this;
            }

            public Builder clearGmsCoreVersion() {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).clearGmsCoreVersion();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public boolean hasApiLevel() {
                return ((ConfigFetchRequest) this.instance).hasApiLevel();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public int getApiLevel() {
                return ((ConfigFetchRequest) this.instance).getApiLevel();
            }

            public Builder setApiLevel(int value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setApiLevel(value);
                return this;
            }

            public Builder clearApiLevel() {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).clearApiLevel();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public boolean hasDeviceCountry() {
                return ((ConfigFetchRequest) this.instance).hasDeviceCountry();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public String getDeviceCountry() {
                return ((ConfigFetchRequest) this.instance).getDeviceCountry();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public ByteString getDeviceCountryBytes() {
                return ((ConfigFetchRequest) this.instance).getDeviceCountryBytes();
            }

            public Builder setDeviceCountry(String value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setDeviceCountry(value);
                return this;
            }

            public Builder clearDeviceCountry() {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).clearDeviceCountry();
                return this;
            }

            public Builder setDeviceCountryBytes(ByteString value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setDeviceCountryBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public boolean hasDeviceLocale() {
                return ((ConfigFetchRequest) this.instance).hasDeviceLocale();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public String getDeviceLocale() {
                return ((ConfigFetchRequest) this.instance).getDeviceLocale();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public ByteString getDeviceLocaleBytes() {
                return ((ConfigFetchRequest) this.instance).getDeviceLocaleBytes();
            }

            public Builder setDeviceLocale(String value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setDeviceLocale(value);
                return this;
            }

            public Builder clearDeviceLocale() {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).clearDeviceLocale();
                return this;
            }

            public Builder setDeviceLocaleBytes(ByteString value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setDeviceLocaleBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public boolean hasDeviceType() {
                return ((ConfigFetchRequest) this.instance).hasDeviceType();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public int getDeviceType() {
                return ((ConfigFetchRequest) this.instance).getDeviceType();
            }

            public Builder setDeviceType(int value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setDeviceType(value);
                return this;
            }

            public Builder clearDeviceType() {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).clearDeviceType();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public boolean hasDeviceSubtype() {
                return ((ConfigFetchRequest) this.instance).hasDeviceSubtype();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public int getDeviceSubtype() {
                return ((ConfigFetchRequest) this.instance).getDeviceSubtype();
            }

            public Builder setDeviceSubtype(int value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setDeviceSubtype(value);
                return this;
            }

            public Builder clearDeviceSubtype() {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).clearDeviceSubtype();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public boolean hasOsVersion() {
                return ((ConfigFetchRequest) this.instance).hasOsVersion();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public String getOsVersion() {
                return ((ConfigFetchRequest) this.instance).getOsVersion();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public ByteString getOsVersionBytes() {
                return ((ConfigFetchRequest) this.instance).getOsVersionBytes();
            }

            public Builder setOsVersion(String value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setOsVersion(value);
                return this;
            }

            public Builder clearOsVersion() {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).clearOsVersion();
                return this;
            }

            public Builder setOsVersionBytes(ByteString value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setOsVersionBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public boolean hasDeviceTimezoneId() {
                return ((ConfigFetchRequest) this.instance).hasDeviceTimezoneId();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public String getDeviceTimezoneId() {
                return ((ConfigFetchRequest) this.instance).getDeviceTimezoneId();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchRequestOrBuilder
            public ByteString getDeviceTimezoneIdBytes() {
                return ((ConfigFetchRequest) this.instance).getDeviceTimezoneIdBytes();
            }

            public Builder setDeviceTimezoneId(String value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setDeviceTimezoneId(value);
                return this;
            }

            public Builder clearDeviceTimezoneId() {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).clearDeviceTimezoneId();
                return this;
            }

            public Builder setDeviceTimezoneIdBytes(ByteString value) {
                copyOnWrite();
                ((ConfigFetchRequest) this.instance).setDeviceTimezoneIdBytes(value);
                return this;
            }
        }

        @Override // com.google.protobuf.GeneratedMessageLite
        protected final Object dynamicMethod(GeneratedMessageLite.MethodToInvoke method, Object arg0, Object arg1) {
            AnonymousClass1 anonymousClass1 = null;
            switch (AnonymousClass1.$SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[method.ordinal()]) {
                case 1:
                    return new ConfigFetchRequest();
                case 2:
                    return DEFAULT_INSTANCE;
                case 3:
                    this.packageData_.makeImmutable();
                    return null;
                case 4:
                    return new Builder(anonymousClass1);
                case 5:
                    GeneratedMessageLite.Visitor visitor = (GeneratedMessageLite.Visitor) arg0;
                    ConfigFetchRequest other = (ConfigFetchRequest) arg1;
                    this.config_ = (Logs.AndroidConfigFetchProto) visitor.visitMessage(this.config_, other.config_);
                    this.androidId_ = visitor.visitLong(hasAndroidId(), this.androidId_, other.hasAndroidId(), other.androidId_);
                    this.packageData_ = visitor.visitList(this.packageData_, other.packageData_);
                    this.deviceDataVersionInfo_ = visitor.visitString(hasDeviceDataVersionInfo(), this.deviceDataVersionInfo_, other.hasDeviceDataVersionInfo(), other.deviceDataVersionInfo_);
                    this.securityToken_ = visitor.visitLong(hasSecurityToken(), this.securityToken_, other.hasSecurityToken(), other.securityToken_);
                    this.clientVersion_ = visitor.visitInt(hasClientVersion(), this.clientVersion_, other.hasClientVersion(), other.clientVersion_);
                    this.gmsCoreVersion_ = visitor.visitInt(hasGmsCoreVersion(), this.gmsCoreVersion_, other.hasGmsCoreVersion(), other.gmsCoreVersion_);
                    this.apiLevel_ = visitor.visitInt(hasApiLevel(), this.apiLevel_, other.hasApiLevel(), other.apiLevel_);
                    this.deviceCountry_ = visitor.visitString(hasDeviceCountry(), this.deviceCountry_, other.hasDeviceCountry(), other.deviceCountry_);
                    this.deviceLocale_ = visitor.visitString(hasDeviceLocale(), this.deviceLocale_, other.hasDeviceLocale(), other.deviceLocale_);
                    this.deviceType_ = visitor.visitInt(hasDeviceType(), this.deviceType_, other.hasDeviceType(), other.deviceType_);
                    this.deviceSubtype_ = visitor.visitInt(hasDeviceSubtype(), this.deviceSubtype_, other.hasDeviceSubtype(), other.deviceSubtype_);
                    this.osVersion_ = visitor.visitString(hasOsVersion(), this.osVersion_, other.hasOsVersion(), other.osVersion_);
                    this.deviceTimezoneId_ = visitor.visitString(hasDeviceTimezoneId(), this.deviceTimezoneId_, other.hasDeviceTimezoneId(), other.deviceTimezoneId_);
                    if (visitor == GeneratedMessageLite.MergeFromVisitor.INSTANCE) {
                        this.bitField0_ |= other.bitField0_;
                    }
                    return this;
                case 6:
                    CodedInputStream input = (CodedInputStream) arg0;
                    ExtensionRegistryLite extensionRegistry = (ExtensionRegistryLite) arg1;
                    boolean done = false;
                    while (!done) {
                        try {
                            int tag = input.readTag();
                            switch (tag) {
                                case 0:
                                    done = true;
                                    break;
                                case 9:
                                    this.bitField0_ |= 2;
                                    this.androidId_ = input.readFixed64();
                                    break;
                                case 18:
                                    if (!this.packageData_.isModifiable()) {
                                        this.packageData_ = GeneratedMessageLite.mutableCopy(this.packageData_);
                                    }
                                    this.packageData_.add((PackageData) input.readMessage(PackageData.parser(), extensionRegistry));
                                    break;
                                case 26:
                                    String s = input.readString();
                                    this.bitField0_ |= 4;
                                    this.deviceDataVersionInfo_ = s;
                                    break;
                                case 33:
                                    this.bitField0_ |= 8;
                                    this.securityToken_ = input.readFixed64();
                                    break;
                                case 42:
                                    Logs.AndroidConfigFetchProto.Builder subBuilder = null;
                                    if ((this.bitField0_ & 1) == 1) {
                                        subBuilder = this.config_.toBuilder();
                                    }
                                    Logs.AndroidConfigFetchProto androidConfigFetchProto = (Logs.AndroidConfigFetchProto) input.readMessage(Logs.AndroidConfigFetchProto.parser(), extensionRegistry);
                                    this.config_ = androidConfigFetchProto;
                                    if (subBuilder != null) {
                                        subBuilder.mergeFrom(androidConfigFetchProto);
                                        this.config_ = (Logs.AndroidConfigFetchProto) subBuilder.buildPartial();
                                    }
                                    this.bitField0_ |= 1;
                                    break;
                                case 48:
                                    this.bitField0_ |= 16;
                                    this.clientVersion_ = input.readInt32();
                                    break;
                                case 56:
                                    this.bitField0_ |= 32;
                                    this.gmsCoreVersion_ = input.readInt32();
                                    break;
                                case 64:
                                    this.bitField0_ |= 64;
                                    this.apiLevel_ = input.readInt32();
                                    break;
                                case 74:
                                    String s2 = input.readString();
                                    this.bitField0_ |= 128;
                                    this.deviceCountry_ = s2;
                                    break;
                                case 82:
                                    String s3 = input.readString();
                                    this.bitField0_ |= 256;
                                    this.deviceLocale_ = s3;
                                    break;
                                case 88:
                                    this.bitField0_ |= 512;
                                    this.deviceType_ = input.readInt32();
                                    break;
                                case 96:
                                    this.bitField0_ |= 1024;
                                    this.deviceSubtype_ = input.readInt32();
                                    break;
                                case 106:
                                    String s4 = input.readString();
                                    this.bitField0_ |= 2048;
                                    this.osVersion_ = s4;
                                    break;
                                case 114:
                                    String s5 = input.readString();
                                    this.bitField0_ |= 4096;
                                    this.deviceTimezoneId_ = s5;
                                    break;
                                default:
                                    if (!parseUnknownField(tag, input)) {
                                        done = true;
                                    }
                                    break;
                            }
                        } catch (InvalidProtocolBufferException e) {
                            throw new RuntimeException(e.setUnfinishedMessage(this));
                        } catch (IOException e2) {
                            throw new RuntimeException(new InvalidProtocolBufferException(e2.getMessage()).setUnfinishedMessage(this));
                        }
                    }
                    break;
                case 7:
                    break;
                case 8:
                    if (PARSER == null) {
                        synchronized (ConfigFetchRequest.class) {
                            if (PARSER == null) {
                                PARSER = new GeneratedMessageLite.DefaultInstanceBasedParser(DEFAULT_INSTANCE);
                            }
                            break;
                        }
                    }
                    return PARSER;
                default:
                    throw new UnsupportedOperationException();
            }
            return DEFAULT_INSTANCE;
        }

        static {
            ConfigFetchRequest configFetchRequest = new ConfigFetchRequest();
            DEFAULT_INSTANCE = configFetchRequest;
            configFetchRequest.makeImmutable();
        }

        public static ConfigFetchRequest getDefaultInstance() {
            return DEFAULT_INSTANCE;
        }

        public static Parser<ConfigFetchRequest> parser() {
            return DEFAULT_INSTANCE.getParserForType();
        }
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public static final class PackageTable extends GeneratedMessageLite<PackageTable, Builder> implements PackageTableOrBuilder {
        public static final int CONFIG_ID_FIELD_NUMBER = 3;
        private static final PackageTable DEFAULT_INSTANCE;
        public static final int ENTRY_FIELD_NUMBER = 2;
        public static final int PACKAGE_NAME_FIELD_NUMBER = 1;
        private static volatile Parser<PackageTable> PARSER;
        private int bitField0_;
        private String packageName_ = "";
        private Internal.ProtobufList<KeyValue> entry_ = emptyProtobufList();
        private String configId_ = "";

        private PackageTable() {
        }

        @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
        public boolean hasPackageName() {
            return (this.bitField0_ & 1) == 1;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
        public String getPackageName() {
            return this.packageName_;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
        public ByteString getPackageNameBytes() {
            return ByteString.copyFromUtf8(this.packageName_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setPackageName(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 1;
            this.packageName_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearPackageName() {
            this.bitField0_ &= -2;
            this.packageName_ = getDefaultInstance().getPackageName();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setPackageNameBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 1;
            this.packageName_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
        public List<KeyValue> getEntryList() {
            return this.entry_;
        }

        public List<? extends KeyValueOrBuilder> getEntryOrBuilderList() {
            return this.entry_;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
        public int getEntryCount() {
            return this.entry_.size();
        }

        @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
        public KeyValue getEntry(int index) {
            return this.entry_.get(index);
        }

        public KeyValueOrBuilder getEntryOrBuilder(int index) {
            return this.entry_.get(index);
        }

        private void ensureEntryIsMutable() {
            if (!this.entry_.isModifiable()) {
                this.entry_ = GeneratedMessageLite.mutableCopy(this.entry_);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setEntry(int index, KeyValue value) {
            if (value == null) {
                throw null;
            }
            ensureEntryIsMutable();
            this.entry_.set(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setEntry(int index, KeyValue.Builder builderForValue) {
            ensureEntryIsMutable();
            this.entry_.set(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addEntry(KeyValue value) {
            if (value == null) {
                throw null;
            }
            ensureEntryIsMutable();
            this.entry_.add(value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addEntry(int index, KeyValue value) {
            if (value == null) {
                throw null;
            }
            ensureEntryIsMutable();
            this.entry_.add(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addEntry(KeyValue.Builder builderForValue) {
            ensureEntryIsMutable();
            this.entry_.add(builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addEntry(int index, KeyValue.Builder builderForValue) {
            ensureEntryIsMutable();
            this.entry_.add(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAllEntry(Iterable<? extends KeyValue> values) {
            ensureEntryIsMutable();
            AbstractMessageLite.addAll(values, this.entry_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearEntry() {
            this.entry_ = emptyProtobufList();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void removeEntry(int index) {
            ensureEntryIsMutable();
            this.entry_.remove(index);
        }

        @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
        public boolean hasConfigId() {
            return (this.bitField0_ & 2) == 2;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
        public String getConfigId() {
            return this.configId_;
        }

        @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
        public ByteString getConfigIdBytes() {
            return ByteString.copyFromUtf8(this.configId_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setConfigId(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 2;
            this.configId_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearConfigId() {
            this.bitField0_ &= -3;
            this.configId_ = getDefaultInstance().getConfigId();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setConfigIdBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 2;
            this.configId_ = value.toStringUtf8();
        }

        @Override // com.google.protobuf.MessageLite
        public void writeTo(CodedOutputStream output) throws IOException {
            if ((this.bitField0_ & 1) == 1) {
                output.writeString(1, getPackageName());
            }
            for (int i = 0; i < this.entry_.size(); i++) {
                output.writeMessage(2, this.entry_.get(i));
            }
            int i2 = this.bitField0_;
            if ((i2 & 2) == 2) {
                output.writeString(3, getConfigId());
            }
            this.unknownFields.writeTo(output);
        }

        @Override // com.google.protobuf.MessageLite
        public int getSerializedSize() {
            int size = this.memoizedSerializedSize;
            if (size != -1) {
                return size;
            }
            int size2 = (this.bitField0_ & 1) == 1 ? 0 + CodedOutputStream.computeStringSize(1, getPackageName()) : 0;
            for (int i = 0; i < this.entry_.size(); i++) {
                size2 += CodedOutputStream.computeMessageSize(2, this.entry_.get(i));
            }
            int i2 = this.bitField0_;
            if ((i2 & 2) == 2) {
                size2 += CodedOutputStream.computeStringSize(3, getConfigId());
            }
            int size3 = size2 + this.unknownFields.getSerializedSize();
            this.memoizedSerializedSize = size3;
            return size3;
        }

        public static PackageTable parseFrom(ByteString data) throws InvalidProtocolBufferException {
            return (PackageTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static PackageTable parseFrom(ByteString data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (PackageTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static PackageTable parseFrom(byte[] data) throws InvalidProtocolBufferException {
            return (PackageTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static PackageTable parseFrom(byte[] data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (PackageTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static PackageTable parseFrom(InputStream input) throws IOException {
            return (PackageTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static PackageTable parseFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (PackageTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static PackageTable parseDelimitedFrom(InputStream input) throws IOException {
            return (PackageTable) parseDelimitedFrom(DEFAULT_INSTANCE, input);
        }

        public static PackageTable parseDelimitedFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (PackageTable) parseDelimitedFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static PackageTable parseFrom(CodedInputStream input) throws IOException {
            return (PackageTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static PackageTable parseFrom(CodedInputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (PackageTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static Builder newBuilder() {
            return DEFAULT_INSTANCE.toBuilder();
        }

        public static Builder newBuilder(PackageTable prototype) {
            return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
        }

        /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
        public static final class Builder extends GeneratedMessageLite.Builder<PackageTable, Builder> implements PackageTableOrBuilder {
            /* synthetic */ Builder(AnonymousClass1 x0) {
                this();
            }

            private Builder() {
                super(PackageTable.DEFAULT_INSTANCE);
            }

            @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
            public boolean hasPackageName() {
                return ((PackageTable) this.instance).hasPackageName();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
            public String getPackageName() {
                return ((PackageTable) this.instance).getPackageName();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
            public ByteString getPackageNameBytes() {
                return ((PackageTable) this.instance).getPackageNameBytes();
            }

            public Builder setPackageName(String value) {
                copyOnWrite();
                ((PackageTable) this.instance).setPackageName(value);
                return this;
            }

            public Builder clearPackageName() {
                copyOnWrite();
                ((PackageTable) this.instance).clearPackageName();
                return this;
            }

            public Builder setPackageNameBytes(ByteString value) {
                copyOnWrite();
                ((PackageTable) this.instance).setPackageNameBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
            public List<KeyValue> getEntryList() {
                return Collections.unmodifiableList(((PackageTable) this.instance).getEntryList());
            }

            @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
            public int getEntryCount() {
                return ((PackageTable) this.instance).getEntryCount();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
            public KeyValue getEntry(int index) {
                return ((PackageTable) this.instance).getEntry(index);
            }

            public Builder setEntry(int index, KeyValue value) {
                copyOnWrite();
                ((PackageTable) this.instance).setEntry(index, value);
                return this;
            }

            public Builder setEntry(int index, KeyValue.Builder builderForValue) {
                copyOnWrite();
                ((PackageTable) this.instance).setEntry(index, builderForValue);
                return this;
            }

            public Builder addEntry(KeyValue value) {
                copyOnWrite();
                ((PackageTable) this.instance).addEntry(value);
                return this;
            }

            public Builder addEntry(int index, KeyValue value) {
                copyOnWrite();
                ((PackageTable) this.instance).addEntry(index, value);
                return this;
            }

            public Builder addEntry(KeyValue.Builder builderForValue) {
                copyOnWrite();
                ((PackageTable) this.instance).addEntry(builderForValue);
                return this;
            }

            public Builder addEntry(int index, KeyValue.Builder builderForValue) {
                copyOnWrite();
                ((PackageTable) this.instance).addEntry(index, builderForValue);
                return this;
            }

            public Builder addAllEntry(Iterable<? extends KeyValue> values) {
                copyOnWrite();
                ((PackageTable) this.instance).addAllEntry(values);
                return this;
            }

            public Builder clearEntry() {
                copyOnWrite();
                ((PackageTable) this.instance).clearEntry();
                return this;
            }

            public Builder removeEntry(int index) {
                copyOnWrite();
                ((PackageTable) this.instance).removeEntry(index);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
            public boolean hasConfigId() {
                return ((PackageTable) this.instance).hasConfigId();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
            public String getConfigId() {
                return ((PackageTable) this.instance).getConfigId();
            }

            @Override // com.google.android.gms.config.proto.Config.PackageTableOrBuilder
            public ByteString getConfigIdBytes() {
                return ((PackageTable) this.instance).getConfigIdBytes();
            }

            public Builder setConfigId(String value) {
                copyOnWrite();
                ((PackageTable) this.instance).setConfigId(value);
                return this;
            }

            public Builder clearConfigId() {
                copyOnWrite();
                ((PackageTable) this.instance).clearConfigId();
                return this;
            }

            public Builder setConfigIdBytes(ByteString value) {
                copyOnWrite();
                ((PackageTable) this.instance).setConfigIdBytes(value);
                return this;
            }
        }

        @Override // com.google.protobuf.GeneratedMessageLite
        protected final Object dynamicMethod(GeneratedMessageLite.MethodToInvoke method, Object arg0, Object arg1) {
            AnonymousClass1 anonymousClass1 = null;
            switch (AnonymousClass1.$SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[method.ordinal()]) {
                case 1:
                    return new PackageTable();
                case 2:
                    return DEFAULT_INSTANCE;
                case 3:
                    this.entry_.makeImmutable();
                    return null;
                case 4:
                    return new Builder(anonymousClass1);
                case 5:
                    GeneratedMessageLite.Visitor visitor = (GeneratedMessageLite.Visitor) arg0;
                    PackageTable other = (PackageTable) arg1;
                    this.packageName_ = visitor.visitString(hasPackageName(), this.packageName_, other.hasPackageName(), other.packageName_);
                    this.entry_ = visitor.visitList(this.entry_, other.entry_);
                    this.configId_ = visitor.visitString(hasConfigId(), this.configId_, other.hasConfigId(), other.configId_);
                    if (visitor == GeneratedMessageLite.MergeFromVisitor.INSTANCE) {
                        this.bitField0_ |= other.bitField0_;
                    }
                    return this;
                case 6:
                    CodedInputStream input = (CodedInputStream) arg0;
                    ExtensionRegistryLite extensionRegistry = (ExtensionRegistryLite) arg1;
                    boolean done = false;
                    while (!done) {
                        try {
                            int tag = input.readTag();
                            if (tag == 0) {
                                done = true;
                            } else if (tag == 10) {
                                String s = input.readString();
                                this.bitField0_ |= 1;
                                this.packageName_ = s;
                            } else if (tag == 18) {
                                if (!this.entry_.isModifiable()) {
                                    this.entry_ = GeneratedMessageLite.mutableCopy(this.entry_);
                                }
                                this.entry_.add((KeyValue) input.readMessage(KeyValue.parser(), extensionRegistry));
                            } else if (tag != 26) {
                                if (!parseUnknownField(tag, input)) {
                                    done = true;
                                }
                            } else {
                                String s2 = input.readString();
                                this.bitField0_ |= 2;
                                this.configId_ = s2;
                            }
                        } catch (InvalidProtocolBufferException e) {
                            throw new RuntimeException(e.setUnfinishedMessage(this));
                        } catch (IOException e2) {
                            throw new RuntimeException(new InvalidProtocolBufferException(e2.getMessage()).setUnfinishedMessage(this));
                        }
                    }
                    break;
                case 7:
                    break;
                case 8:
                    if (PARSER == null) {
                        synchronized (PackageTable.class) {
                            if (PARSER == null) {
                                PARSER = new GeneratedMessageLite.DefaultInstanceBasedParser(DEFAULT_INSTANCE);
                            }
                            break;
                        }
                    }
                    return PARSER;
                default:
                    throw new UnsupportedOperationException();
            }
            return DEFAULT_INSTANCE;
        }

        static {
            PackageTable packageTable = new PackageTable();
            DEFAULT_INSTANCE = packageTable;
            packageTable.makeImmutable();
        }

        public static PackageTable getDefaultInstance() {
            return DEFAULT_INSTANCE;
        }

        public static Parser<PackageTable> parser() {
            return DEFAULT_INSTANCE.getParserForType();
        }
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public static final class AppNamespaceConfigTable extends GeneratedMessageLite<AppNamespaceConfigTable, Builder> implements AppNamespaceConfigTableOrBuilder {
        private static final AppNamespaceConfigTable DEFAULT_INSTANCE;
        public static final int DIGEST_FIELD_NUMBER = 2;
        public static final int ENTRY_FIELD_NUMBER = 3;
        public static final int NAMESPACE_FIELD_NUMBER = 1;
        private static volatile Parser<AppNamespaceConfigTable> PARSER = null;
        public static final int STATUS_FIELD_NUMBER = 4;
        private int bitField0_;
        private int status_;
        private String namespace_ = "";
        private String digest_ = "";
        private Internal.ProtobufList<KeyValue> entry_ = emptyProtobufList();

        private AppNamespaceConfigTable() {
        }

        /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
        public enum NamespaceStatus implements Internal.EnumLite {
            UPDATE(0),
            NO_TEMPLATE(1),
            NO_CHANGE(2),
            EMPTY_CONFIG(3),
            NOT_AUTHORIZED(4);

            public static final int EMPTY_CONFIG_VALUE = 3;
            public static final int NOT_AUTHORIZED_VALUE = 4;
            public static final int NO_CHANGE_VALUE = 2;
            public static final int NO_TEMPLATE_VALUE = 1;
            public static final int UPDATE_VALUE = 0;
            private static final Internal.EnumLiteMap<NamespaceStatus> internalValueMap = new Internal.EnumLiteMap<NamespaceStatus>() { // from class: com.google.android.gms.config.proto.Config.AppNamespaceConfigTable.NamespaceStatus.1
                @Override // com.google.protobuf.Internal.EnumLiteMap
                public NamespaceStatus findValueByNumber(int number) {
                    return NamespaceStatus.forNumber(number);
                }
            };
            private final int value;

            @Override // com.google.protobuf.Internal.EnumLite
            public final int getNumber() {
                return this.value;
            }

            @Deprecated
            public static NamespaceStatus valueOf(int value) {
                return forNumber(value);
            }

            public static NamespaceStatus forNumber(int value) {
                if (value == 0) {
                    return UPDATE;
                }
                if (value == 1) {
                    return NO_TEMPLATE;
                }
                if (value == 2) {
                    return NO_CHANGE;
                }
                if (value == 3) {
                    return EMPTY_CONFIG;
                }
                if (value == 4) {
                    return NOT_AUTHORIZED;
                }
                return null;
            }

            public static Internal.EnumLiteMap<NamespaceStatus> internalGetValueMap() {
                return internalValueMap;
            }

            NamespaceStatus(int value) {
                this.value = value;
            }
        }

        @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
        public boolean hasNamespace() {
            return (this.bitField0_ & 1) == 1;
        }

        @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
        public String getNamespace() {
            return this.namespace_;
        }

        @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
        public ByteString getNamespaceBytes() {
            return ByteString.copyFromUtf8(this.namespace_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setNamespace(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 1;
            this.namespace_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearNamespace() {
            this.bitField0_ &= -2;
            this.namespace_ = getDefaultInstance().getNamespace();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setNamespaceBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 1;
            this.namespace_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
        public boolean hasDigest() {
            return (this.bitField0_ & 2) == 2;
        }

        @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
        public String getDigest() {
            return this.digest_;
        }

        @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
        public ByteString getDigestBytes() {
            return ByteString.copyFromUtf8(this.digest_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setDigest(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 2;
            this.digest_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearDigest() {
            this.bitField0_ &= -3;
            this.digest_ = getDefaultInstance().getDigest();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setDigestBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 2;
            this.digest_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
        public List<KeyValue> getEntryList() {
            return this.entry_;
        }

        public List<? extends KeyValueOrBuilder> getEntryOrBuilderList() {
            return this.entry_;
        }

        @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
        public int getEntryCount() {
            return this.entry_.size();
        }

        @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
        public KeyValue getEntry(int index) {
            return this.entry_.get(index);
        }

        public KeyValueOrBuilder getEntryOrBuilder(int index) {
            return this.entry_.get(index);
        }

        private void ensureEntryIsMutable() {
            if (!this.entry_.isModifiable()) {
                this.entry_ = GeneratedMessageLite.mutableCopy(this.entry_);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setEntry(int index, KeyValue value) {
            if (value == null) {
                throw null;
            }
            ensureEntryIsMutable();
            this.entry_.set(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setEntry(int index, KeyValue.Builder builderForValue) {
            ensureEntryIsMutable();
            this.entry_.set(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addEntry(KeyValue value) {
            if (value == null) {
                throw null;
            }
            ensureEntryIsMutable();
            this.entry_.add(value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addEntry(int index, KeyValue value) {
            if (value == null) {
                throw null;
            }
            ensureEntryIsMutable();
            this.entry_.add(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addEntry(KeyValue.Builder builderForValue) {
            ensureEntryIsMutable();
            this.entry_.add(builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addEntry(int index, KeyValue.Builder builderForValue) {
            ensureEntryIsMutable();
            this.entry_.add(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAllEntry(Iterable<? extends KeyValue> values) {
            ensureEntryIsMutable();
            AbstractMessageLite.addAll(values, this.entry_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearEntry() {
            this.entry_ = emptyProtobufList();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void removeEntry(int index) {
            ensureEntryIsMutable();
            this.entry_.remove(index);
        }

        @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
        public boolean hasStatus() {
            return (this.bitField0_ & 4) == 4;
        }

        @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
        public NamespaceStatus getStatus() {
            NamespaceStatus result = NamespaceStatus.forNumber(this.status_);
            return result == null ? NamespaceStatus.UPDATE : result;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setStatus(NamespaceStatus value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 4;
            this.status_ = value.getNumber();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearStatus() {
            this.bitField0_ &= -5;
            this.status_ = 0;
        }

        @Override // com.google.protobuf.MessageLite
        public void writeTo(CodedOutputStream output) throws IOException {
            if ((this.bitField0_ & 1) == 1) {
                output.writeString(1, getNamespace());
            }
            if ((this.bitField0_ & 2) == 2) {
                output.writeString(2, getDigest());
            }
            for (int i = 0; i < this.entry_.size(); i++) {
                output.writeMessage(3, this.entry_.get(i));
            }
            int i2 = this.bitField0_;
            if ((i2 & 4) == 4) {
                output.writeEnum(4, this.status_);
            }
            this.unknownFields.writeTo(output);
        }

        @Override // com.google.protobuf.MessageLite
        public int getSerializedSize() {
            int size = this.memoizedSerializedSize;
            if (size != -1) {
                return size;
            }
            int size2 = (this.bitField0_ & 1) == 1 ? 0 + CodedOutputStream.computeStringSize(1, getNamespace()) : 0;
            if ((this.bitField0_ & 2) == 2) {
                size2 += CodedOutputStream.computeStringSize(2, getDigest());
            }
            for (int i = 0; i < this.entry_.size(); i++) {
                size2 += CodedOutputStream.computeMessageSize(3, this.entry_.get(i));
            }
            int i2 = this.bitField0_;
            if ((i2 & 4) == 4) {
                size2 += CodedOutputStream.computeEnumSize(4, this.status_);
            }
            int size3 = size2 + this.unknownFields.getSerializedSize();
            this.memoizedSerializedSize = size3;
            return size3;
        }

        public static AppNamespaceConfigTable parseFrom(ByteString data) throws InvalidProtocolBufferException {
            return (AppNamespaceConfigTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static AppNamespaceConfigTable parseFrom(ByteString data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (AppNamespaceConfigTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static AppNamespaceConfigTable parseFrom(byte[] data) throws InvalidProtocolBufferException {
            return (AppNamespaceConfigTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static AppNamespaceConfigTable parseFrom(byte[] data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (AppNamespaceConfigTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static AppNamespaceConfigTable parseFrom(InputStream input) throws IOException {
            return (AppNamespaceConfigTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static AppNamespaceConfigTable parseFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (AppNamespaceConfigTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static AppNamespaceConfigTable parseDelimitedFrom(InputStream input) throws IOException {
            return (AppNamespaceConfigTable) parseDelimitedFrom(DEFAULT_INSTANCE, input);
        }

        public static AppNamespaceConfigTable parseDelimitedFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (AppNamespaceConfigTable) parseDelimitedFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static AppNamespaceConfigTable parseFrom(CodedInputStream input) throws IOException {
            return (AppNamespaceConfigTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static AppNamespaceConfigTable parseFrom(CodedInputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (AppNamespaceConfigTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static Builder newBuilder() {
            return DEFAULT_INSTANCE.toBuilder();
        }

        public static Builder newBuilder(AppNamespaceConfigTable prototype) {
            return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
        }

        /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
        public static final class Builder extends GeneratedMessageLite.Builder<AppNamespaceConfigTable, Builder> implements AppNamespaceConfigTableOrBuilder {
            /* synthetic */ Builder(AnonymousClass1 x0) {
                this();
            }

            private Builder() {
                super(AppNamespaceConfigTable.DEFAULT_INSTANCE);
            }

            @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
            public boolean hasNamespace() {
                return ((AppNamespaceConfigTable) this.instance).hasNamespace();
            }

            @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
            public String getNamespace() {
                return ((AppNamespaceConfigTable) this.instance).getNamespace();
            }

            @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
            public ByteString getNamespaceBytes() {
                return ((AppNamespaceConfigTable) this.instance).getNamespaceBytes();
            }

            public Builder setNamespace(String value) {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).setNamespace(value);
                return this;
            }

            public Builder clearNamespace() {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).clearNamespace();
                return this;
            }

            public Builder setNamespaceBytes(ByteString value) {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).setNamespaceBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
            public boolean hasDigest() {
                return ((AppNamespaceConfigTable) this.instance).hasDigest();
            }

            @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
            public String getDigest() {
                return ((AppNamespaceConfigTable) this.instance).getDigest();
            }

            @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
            public ByteString getDigestBytes() {
                return ((AppNamespaceConfigTable) this.instance).getDigestBytes();
            }

            public Builder setDigest(String value) {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).setDigest(value);
                return this;
            }

            public Builder clearDigest() {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).clearDigest();
                return this;
            }

            public Builder setDigestBytes(ByteString value) {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).setDigestBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
            public List<KeyValue> getEntryList() {
                return Collections.unmodifiableList(((AppNamespaceConfigTable) this.instance).getEntryList());
            }

            @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
            public int getEntryCount() {
                return ((AppNamespaceConfigTable) this.instance).getEntryCount();
            }

            @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
            public KeyValue getEntry(int index) {
                return ((AppNamespaceConfigTable) this.instance).getEntry(index);
            }

            public Builder setEntry(int index, KeyValue value) {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).setEntry(index, value);
                return this;
            }

            public Builder setEntry(int index, KeyValue.Builder builderForValue) {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).setEntry(index, builderForValue);
                return this;
            }

            public Builder addEntry(KeyValue value) {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).addEntry(value);
                return this;
            }

            public Builder addEntry(int index, KeyValue value) {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).addEntry(index, value);
                return this;
            }

            public Builder addEntry(KeyValue.Builder builderForValue) {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).addEntry(builderForValue);
                return this;
            }

            public Builder addEntry(int index, KeyValue.Builder builderForValue) {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).addEntry(index, builderForValue);
                return this;
            }

            public Builder addAllEntry(Iterable<? extends KeyValue> values) {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).addAllEntry(values);
                return this;
            }

            public Builder clearEntry() {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).clearEntry();
                return this;
            }

            public Builder removeEntry(int index) {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).removeEntry(index);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
            public boolean hasStatus() {
                return ((AppNamespaceConfigTable) this.instance).hasStatus();
            }

            @Override // com.google.android.gms.config.proto.Config.AppNamespaceConfigTableOrBuilder
            public NamespaceStatus getStatus() {
                return ((AppNamespaceConfigTable) this.instance).getStatus();
            }

            public Builder setStatus(NamespaceStatus value) {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).setStatus(value);
                return this;
            }

            public Builder clearStatus() {
                copyOnWrite();
                ((AppNamespaceConfigTable) this.instance).clearStatus();
                return this;
            }
        }

        @Override // com.google.protobuf.GeneratedMessageLite
        protected final Object dynamicMethod(GeneratedMessageLite.MethodToInvoke method, Object arg0, Object arg1) {
            AnonymousClass1 anonymousClass1 = null;
            switch (AnonymousClass1.$SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[method.ordinal()]) {
                case 1:
                    return new AppNamespaceConfigTable();
                case 2:
                    return DEFAULT_INSTANCE;
                case 3:
                    this.entry_.makeImmutable();
                    return null;
                case 4:
                    return new Builder(anonymousClass1);
                case 5:
                    GeneratedMessageLite.Visitor visitor = (GeneratedMessageLite.Visitor) arg0;
                    AppNamespaceConfigTable other = (AppNamespaceConfigTable) arg1;
                    this.namespace_ = visitor.visitString(hasNamespace(), this.namespace_, other.hasNamespace(), other.namespace_);
                    this.digest_ = visitor.visitString(hasDigest(), this.digest_, other.hasDigest(), other.digest_);
                    this.entry_ = visitor.visitList(this.entry_, other.entry_);
                    this.status_ = visitor.visitInt(hasStatus(), this.status_, other.hasStatus(), other.status_);
                    if (visitor == GeneratedMessageLite.MergeFromVisitor.INSTANCE) {
                        this.bitField0_ |= other.bitField0_;
                    }
                    return this;
                case 6:
                    CodedInputStream input = (CodedInputStream) arg0;
                    ExtensionRegistryLite extensionRegistry = (ExtensionRegistryLite) arg1;
                    boolean done = false;
                    while (!done) {
                        try {
                            try {
                                int tag = input.readTag();
                                if (tag == 0) {
                                    done = true;
                                } else if (tag == 10) {
                                    String s = input.readString();
                                    this.bitField0_ |= 1;
                                    this.namespace_ = s;
                                } else if (tag == 18) {
                                    String s2 = input.readString();
                                    this.bitField0_ |= 2;
                                    this.digest_ = s2;
                                } else if (tag == 26) {
                                    if (!this.entry_.isModifiable()) {
                                        this.entry_ = GeneratedMessageLite.mutableCopy(this.entry_);
                                    }
                                    this.entry_.add((KeyValue) input.readMessage(KeyValue.parser(), extensionRegistry));
                                } else if (tag != 32) {
                                    if (!parseUnknownField(tag, input)) {
                                        done = true;
                                    }
                                } else {
                                    int rawValue = input.readEnum();
                                    NamespaceStatus value = NamespaceStatus.forNumber(rawValue);
                                    if (value != null) {
                                        this.bitField0_ = 4 | this.bitField0_;
                                        this.status_ = rawValue;
                                    } else {
                                        super.mergeVarintField(4, rawValue);
                                    }
                                }
                            } catch (InvalidProtocolBufferException e) {
                                throw new RuntimeException(e.setUnfinishedMessage(this));
                            }
                        } catch (IOException e2) {
                            throw new RuntimeException(new InvalidProtocolBufferException(e2.getMessage()).setUnfinishedMessage(this));
                        }
                    }
                    break;
                case 7:
                    break;
                case 8:
                    if (PARSER == null) {
                        synchronized (AppNamespaceConfigTable.class) {
                            if (PARSER == null) {
                                PARSER = new GeneratedMessageLite.DefaultInstanceBasedParser(DEFAULT_INSTANCE);
                            }
                            break;
                        }
                    }
                    return PARSER;
                default:
                    throw new UnsupportedOperationException();
            }
            return DEFAULT_INSTANCE;
        }

        static {
            AppNamespaceConfigTable appNamespaceConfigTable = new AppNamespaceConfigTable();
            DEFAULT_INSTANCE = appNamespaceConfigTable;
            appNamespaceConfigTable.makeImmutable();
        }

        public static AppNamespaceConfigTable getDefaultInstance() {
            return DEFAULT_INSTANCE;
        }

        public static Parser<AppNamespaceConfigTable> parser() {
            return DEFAULT_INSTANCE.getParserForType();
        }
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public static final class AppConfigTable extends GeneratedMessageLite<AppConfigTable, Builder> implements AppConfigTableOrBuilder {
        public static final int APP_NAME_FIELD_NUMBER = 1;
        private static final AppConfigTable DEFAULT_INSTANCE;
        public static final int EXPERIMENT_PAYLOAD_FIELD_NUMBER = 3;
        public static final int NAMESPACE_CONFIG_FIELD_NUMBER = 2;
        private static volatile Parser<AppConfigTable> PARSER;
        private int bitField0_;
        private String appName_ = "";
        private Internal.ProtobufList<AppNamespaceConfigTable> namespaceConfig_ = emptyProtobufList();
        private Internal.ProtobufList<ByteString> experimentPayload_ = emptyProtobufList();

        private AppConfigTable() {
        }

        @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
        public boolean hasAppName() {
            return (this.bitField0_ & 1) == 1;
        }

        @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
        public String getAppName() {
            return this.appName_;
        }

        @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
        public ByteString getAppNameBytes() {
            return ByteString.copyFromUtf8(this.appName_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setAppName(String value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 1;
            this.appName_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearAppName() {
            this.bitField0_ &= -2;
            this.appName_ = getDefaultInstance().getAppName();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setAppNameBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 1;
            this.appName_ = value.toStringUtf8();
        }

        @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
        public List<AppNamespaceConfigTable> getNamespaceConfigList() {
            return this.namespaceConfig_;
        }

        public List<? extends AppNamespaceConfigTableOrBuilder> getNamespaceConfigOrBuilderList() {
            return this.namespaceConfig_;
        }

        @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
        public int getNamespaceConfigCount() {
            return this.namespaceConfig_.size();
        }

        @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
        public AppNamespaceConfigTable getNamespaceConfig(int index) {
            return this.namespaceConfig_.get(index);
        }

        public AppNamespaceConfigTableOrBuilder getNamespaceConfigOrBuilder(int index) {
            return this.namespaceConfig_.get(index);
        }

        private void ensureNamespaceConfigIsMutable() {
            if (!this.namespaceConfig_.isModifiable()) {
                this.namespaceConfig_ = GeneratedMessageLite.mutableCopy(this.namespaceConfig_);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setNamespaceConfig(int index, AppNamespaceConfigTable value) {
            if (value == null) {
                throw null;
            }
            ensureNamespaceConfigIsMutable();
            this.namespaceConfig_.set(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setNamespaceConfig(int index, AppNamespaceConfigTable.Builder builderForValue) {
            ensureNamespaceConfigIsMutable();
            this.namespaceConfig_.set(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addNamespaceConfig(AppNamespaceConfigTable value) {
            if (value == null) {
                throw null;
            }
            ensureNamespaceConfigIsMutable();
            this.namespaceConfig_.add(value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addNamespaceConfig(int index, AppNamespaceConfigTable value) {
            if (value == null) {
                throw null;
            }
            ensureNamespaceConfigIsMutable();
            this.namespaceConfig_.add(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addNamespaceConfig(AppNamespaceConfigTable.Builder builderForValue) {
            ensureNamespaceConfigIsMutable();
            this.namespaceConfig_.add(builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addNamespaceConfig(int index, AppNamespaceConfigTable.Builder builderForValue) {
            ensureNamespaceConfigIsMutable();
            this.namespaceConfig_.add(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAllNamespaceConfig(Iterable<? extends AppNamespaceConfigTable> values) {
            ensureNamespaceConfigIsMutable();
            AbstractMessageLite.addAll(values, this.namespaceConfig_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearNamespaceConfig() {
            this.namespaceConfig_ = emptyProtobufList();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void removeNamespaceConfig(int index) {
            ensureNamespaceConfigIsMutable();
            this.namespaceConfig_.remove(index);
        }

        @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
        public List<ByteString> getExperimentPayloadList() {
            return this.experimentPayload_;
        }

        @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
        public int getExperimentPayloadCount() {
            return this.experimentPayload_.size();
        }

        @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
        public ByteString getExperimentPayload(int index) {
            return this.experimentPayload_.get(index);
        }

        private void ensureExperimentPayloadIsMutable() {
            if (!this.experimentPayload_.isModifiable()) {
                this.experimentPayload_ = GeneratedMessageLite.mutableCopy(this.experimentPayload_);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setExperimentPayload(int index, ByteString value) {
            if (value == null) {
                throw null;
            }
            ensureExperimentPayloadIsMutable();
            this.experimentPayload_.set(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addExperimentPayload(ByteString value) {
            if (value == null) {
                throw null;
            }
            ensureExperimentPayloadIsMutable();
            this.experimentPayload_.add(value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAllExperimentPayload(Iterable<? extends ByteString> values) {
            ensureExperimentPayloadIsMutable();
            AbstractMessageLite.addAll(values, this.experimentPayload_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearExperimentPayload() {
            this.experimentPayload_ = emptyProtobufList();
        }

        @Override // com.google.protobuf.MessageLite
        public void writeTo(CodedOutputStream output) throws IOException {
            if ((this.bitField0_ & 1) == 1) {
                output.writeString(1, getAppName());
            }
            for (int i = 0; i < this.namespaceConfig_.size(); i++) {
                output.writeMessage(2, this.namespaceConfig_.get(i));
            }
            for (int i2 = 0; i2 < this.experimentPayload_.size(); i2++) {
                output.writeBytes(3, this.experimentPayload_.get(i2));
            }
            this.unknownFields.writeTo(output);
        }

        @Override // com.google.protobuf.MessageLite
        public int getSerializedSize() {
            int size = this.memoizedSerializedSize;
            if (size != -1) {
                return size;
            }
            int size2 = (this.bitField0_ & 1) == 1 ? 0 + CodedOutputStream.computeStringSize(1, getAppName()) : 0;
            for (int i = 0; i < this.namespaceConfig_.size(); i++) {
                size2 += CodedOutputStream.computeMessageSize(2, this.namespaceConfig_.get(i));
            }
            int dataSize = 0;
            for (int i2 = 0; i2 < this.experimentPayload_.size(); i2++) {
                dataSize += CodedOutputStream.computeBytesSizeNoTag(this.experimentPayload_.get(i2));
            }
            int size3 = size2 + dataSize + (getExperimentPayloadList().size() * 1) + this.unknownFields.getSerializedSize();
            this.memoizedSerializedSize = size3;
            return size3;
        }

        public static AppConfigTable parseFrom(ByteString data) throws InvalidProtocolBufferException {
            return (AppConfigTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static AppConfigTable parseFrom(ByteString data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (AppConfigTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static AppConfigTable parseFrom(byte[] data) throws InvalidProtocolBufferException {
            return (AppConfigTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static AppConfigTable parseFrom(byte[] data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (AppConfigTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static AppConfigTable parseFrom(InputStream input) throws IOException {
            return (AppConfigTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static AppConfigTable parseFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (AppConfigTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static AppConfigTable parseDelimitedFrom(InputStream input) throws IOException {
            return (AppConfigTable) parseDelimitedFrom(DEFAULT_INSTANCE, input);
        }

        public static AppConfigTable parseDelimitedFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (AppConfigTable) parseDelimitedFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static AppConfigTable parseFrom(CodedInputStream input) throws IOException {
            return (AppConfigTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static AppConfigTable parseFrom(CodedInputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (AppConfigTable) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static Builder newBuilder() {
            return DEFAULT_INSTANCE.toBuilder();
        }

        public static Builder newBuilder(AppConfigTable prototype) {
            return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
        }

        /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
        public static final class Builder extends GeneratedMessageLite.Builder<AppConfigTable, Builder> implements AppConfigTableOrBuilder {
            /* synthetic */ Builder(AnonymousClass1 x0) {
                this();
            }

            private Builder() {
                super(AppConfigTable.DEFAULT_INSTANCE);
            }

            @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
            public boolean hasAppName() {
                return ((AppConfigTable) this.instance).hasAppName();
            }

            @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
            public String getAppName() {
                return ((AppConfigTable) this.instance).getAppName();
            }

            @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
            public ByteString getAppNameBytes() {
                return ((AppConfigTable) this.instance).getAppNameBytes();
            }

            public Builder setAppName(String value) {
                copyOnWrite();
                ((AppConfigTable) this.instance).setAppName(value);
                return this;
            }

            public Builder clearAppName() {
                copyOnWrite();
                ((AppConfigTable) this.instance).clearAppName();
                return this;
            }

            public Builder setAppNameBytes(ByteString value) {
                copyOnWrite();
                ((AppConfigTable) this.instance).setAppNameBytes(value);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
            public List<AppNamespaceConfigTable> getNamespaceConfigList() {
                return Collections.unmodifiableList(((AppConfigTable) this.instance).getNamespaceConfigList());
            }

            @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
            public int getNamespaceConfigCount() {
                return ((AppConfigTable) this.instance).getNamespaceConfigCount();
            }

            @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
            public AppNamespaceConfigTable getNamespaceConfig(int index) {
                return ((AppConfigTable) this.instance).getNamespaceConfig(index);
            }

            public Builder setNamespaceConfig(int index, AppNamespaceConfigTable value) {
                copyOnWrite();
                ((AppConfigTable) this.instance).setNamespaceConfig(index, value);
                return this;
            }

            public Builder setNamespaceConfig(int index, AppNamespaceConfigTable.Builder builderForValue) {
                copyOnWrite();
                ((AppConfigTable) this.instance).setNamespaceConfig(index, builderForValue);
                return this;
            }

            public Builder addNamespaceConfig(AppNamespaceConfigTable value) {
                copyOnWrite();
                ((AppConfigTable) this.instance).addNamespaceConfig(value);
                return this;
            }

            public Builder addNamespaceConfig(int index, AppNamespaceConfigTable value) {
                copyOnWrite();
                ((AppConfigTable) this.instance).addNamespaceConfig(index, value);
                return this;
            }

            public Builder addNamespaceConfig(AppNamespaceConfigTable.Builder builderForValue) {
                copyOnWrite();
                ((AppConfigTable) this.instance).addNamespaceConfig(builderForValue);
                return this;
            }

            public Builder addNamespaceConfig(int index, AppNamespaceConfigTable.Builder builderForValue) {
                copyOnWrite();
                ((AppConfigTable) this.instance).addNamespaceConfig(index, builderForValue);
                return this;
            }

            public Builder addAllNamespaceConfig(Iterable<? extends AppNamespaceConfigTable> values) {
                copyOnWrite();
                ((AppConfigTable) this.instance).addAllNamespaceConfig(values);
                return this;
            }

            public Builder clearNamespaceConfig() {
                copyOnWrite();
                ((AppConfigTable) this.instance).clearNamespaceConfig();
                return this;
            }

            public Builder removeNamespaceConfig(int index) {
                copyOnWrite();
                ((AppConfigTable) this.instance).removeNamespaceConfig(index);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
            public List<ByteString> getExperimentPayloadList() {
                return Collections.unmodifiableList(((AppConfigTable) this.instance).getExperimentPayloadList());
            }

            @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
            public int getExperimentPayloadCount() {
                return ((AppConfigTable) this.instance).getExperimentPayloadCount();
            }

            @Override // com.google.android.gms.config.proto.Config.AppConfigTableOrBuilder
            public ByteString getExperimentPayload(int index) {
                return ((AppConfigTable) this.instance).getExperimentPayload(index);
            }

            public Builder setExperimentPayload(int index, ByteString value) {
                copyOnWrite();
                ((AppConfigTable) this.instance).setExperimentPayload(index, value);
                return this;
            }

            public Builder addExperimentPayload(ByteString value) {
                copyOnWrite();
                ((AppConfigTable) this.instance).addExperimentPayload(value);
                return this;
            }

            public Builder addAllExperimentPayload(Iterable<? extends ByteString> values) {
                copyOnWrite();
                ((AppConfigTable) this.instance).addAllExperimentPayload(values);
                return this;
            }

            public Builder clearExperimentPayload() {
                copyOnWrite();
                ((AppConfigTable) this.instance).clearExperimentPayload();
                return this;
            }
        }

        @Override // com.google.protobuf.GeneratedMessageLite
        protected final Object dynamicMethod(GeneratedMessageLite.MethodToInvoke method, Object arg0, Object arg1) {
            AnonymousClass1 anonymousClass1 = null;
            switch (AnonymousClass1.$SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[method.ordinal()]) {
                case 1:
                    return new AppConfigTable();
                case 2:
                    return DEFAULT_INSTANCE;
                case 3:
                    this.namespaceConfig_.makeImmutable();
                    this.experimentPayload_.makeImmutable();
                    return null;
                case 4:
                    return new Builder(anonymousClass1);
                case 5:
                    GeneratedMessageLite.Visitor visitor = (GeneratedMessageLite.Visitor) arg0;
                    AppConfigTable other = (AppConfigTable) arg1;
                    this.appName_ = visitor.visitString(hasAppName(), this.appName_, other.hasAppName(), other.appName_);
                    this.namespaceConfig_ = visitor.visitList(this.namespaceConfig_, other.namespaceConfig_);
                    this.experimentPayload_ = visitor.visitList(this.experimentPayload_, other.experimentPayload_);
                    if (visitor == GeneratedMessageLite.MergeFromVisitor.INSTANCE) {
                        this.bitField0_ |= other.bitField0_;
                    }
                    return this;
                case 6:
                    CodedInputStream input = (CodedInputStream) arg0;
                    ExtensionRegistryLite extensionRegistry = (ExtensionRegistryLite) arg1;
                    boolean done = false;
                    while (!done) {
                        try {
                            int tag = input.readTag();
                            if (tag == 0) {
                                done = true;
                            } else if (tag == 10) {
                                String s = input.readString();
                                this.bitField0_ |= 1;
                                this.appName_ = s;
                            } else if (tag == 18) {
                                if (!this.namespaceConfig_.isModifiable()) {
                                    this.namespaceConfig_ = GeneratedMessageLite.mutableCopy(this.namespaceConfig_);
                                }
                                this.namespaceConfig_.add((AppNamespaceConfigTable) input.readMessage(AppNamespaceConfigTable.parser(), extensionRegistry));
                            } else if (tag != 26) {
                                if (!parseUnknownField(tag, input)) {
                                    done = true;
                                }
                            } else {
                                if (!this.experimentPayload_.isModifiable()) {
                                    this.experimentPayload_ = GeneratedMessageLite.mutableCopy(this.experimentPayload_);
                                }
                                this.experimentPayload_.add(input.readBytes());
                            }
                        } catch (InvalidProtocolBufferException e) {
                            throw new RuntimeException(e.setUnfinishedMessage(this));
                        } catch (IOException e2) {
                            throw new RuntimeException(new InvalidProtocolBufferException(e2.getMessage()).setUnfinishedMessage(this));
                        }
                    }
                    break;
                case 7:
                    break;
                case 8:
                    if (PARSER == null) {
                        synchronized (AppConfigTable.class) {
                            if (PARSER == null) {
                                PARSER = new GeneratedMessageLite.DefaultInstanceBasedParser(DEFAULT_INSTANCE);
                            }
                            break;
                        }
                    }
                    return PARSER;
                default:
                    throw new UnsupportedOperationException();
            }
            return DEFAULT_INSTANCE;
        }

        static {
            AppConfigTable appConfigTable = new AppConfigTable();
            DEFAULT_INSTANCE = appConfigTable;
            appConfigTable.makeImmutable();
        }

        public static AppConfigTable getDefaultInstance() {
            return DEFAULT_INSTANCE;
        }

        public static Parser<AppConfigTable> parser() {
            return DEFAULT_INSTANCE.getParserForType();
        }
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public static final class ConfigFetchResponse extends GeneratedMessageLite<ConfigFetchResponse, Builder> implements ConfigFetchResponseOrBuilder {
        public static final int APP_CONFIG_FIELD_NUMBER = 4;
        private static final ConfigFetchResponse DEFAULT_INSTANCE;
        public static final int INTERNAL_METADATA_FIELD_NUMBER = 3;
        public static final int PACKAGE_TABLE_FIELD_NUMBER = 1;
        private static volatile Parser<ConfigFetchResponse> PARSER = null;
        public static final int STATUS_FIELD_NUMBER = 2;
        private int bitField0_;
        private int status_;
        private Internal.ProtobufList<PackageTable> packageTable_ = emptyProtobufList();
        private Internal.ProtobufList<KeyValue> internalMetadata_ = emptyProtobufList();
        private Internal.ProtobufList<AppConfigTable> appConfig_ = emptyProtobufList();

        private ConfigFetchResponse() {
        }

        /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
        public enum ResponseStatus implements Internal.EnumLite {
            SUCCESS(0),
            NO_PACKAGES_IN_REQUEST(1);

            public static final int NO_PACKAGES_IN_REQUEST_VALUE = 1;
            public static final int SUCCESS_VALUE = 0;
            private static final Internal.EnumLiteMap<ResponseStatus> internalValueMap = new Internal.EnumLiteMap<ResponseStatus>() { // from class: com.google.android.gms.config.proto.Config.ConfigFetchResponse.ResponseStatus.1
                @Override // com.google.protobuf.Internal.EnumLiteMap
                public ResponseStatus findValueByNumber(int number) {
                    return ResponseStatus.forNumber(number);
                }
            };
            private final int value;

            @Override // com.google.protobuf.Internal.EnumLite
            public final int getNumber() {
                return this.value;
            }

            @Deprecated
            public static ResponseStatus valueOf(int value) {
                return forNumber(value);
            }

            public static ResponseStatus forNumber(int value) {
                if (value == 0) {
                    return SUCCESS;
                }
                if (value == 1) {
                    return NO_PACKAGES_IN_REQUEST;
                }
                return null;
            }

            public static Internal.EnumLiteMap<ResponseStatus> internalGetValueMap() {
                return internalValueMap;
            }

            ResponseStatus(int value) {
                this.value = value;
            }
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
        public List<PackageTable> getPackageTableList() {
            return this.packageTable_;
        }

        public List<? extends PackageTableOrBuilder> getPackageTableOrBuilderList() {
            return this.packageTable_;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
        public int getPackageTableCount() {
            return this.packageTable_.size();
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
        public PackageTable getPackageTable(int index) {
            return this.packageTable_.get(index);
        }

        public PackageTableOrBuilder getPackageTableOrBuilder(int index) {
            return this.packageTable_.get(index);
        }

        private void ensurePackageTableIsMutable() {
            if (!this.packageTable_.isModifiable()) {
                this.packageTable_ = GeneratedMessageLite.mutableCopy(this.packageTable_);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setPackageTable(int index, PackageTable value) {
            if (value == null) {
                throw null;
            }
            ensurePackageTableIsMutable();
            this.packageTable_.set(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setPackageTable(int index, PackageTable.Builder builderForValue) {
            ensurePackageTableIsMutable();
            this.packageTable_.set(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addPackageTable(PackageTable value) {
            if (value == null) {
                throw null;
            }
            ensurePackageTableIsMutable();
            this.packageTable_.add(value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addPackageTable(int index, PackageTable value) {
            if (value == null) {
                throw null;
            }
            ensurePackageTableIsMutable();
            this.packageTable_.add(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addPackageTable(PackageTable.Builder builderForValue) {
            ensurePackageTableIsMutable();
            this.packageTable_.add(builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addPackageTable(int index, PackageTable.Builder builderForValue) {
            ensurePackageTableIsMutable();
            this.packageTable_.add(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAllPackageTable(Iterable<? extends PackageTable> values) {
            ensurePackageTableIsMutable();
            AbstractMessageLite.addAll(values, this.packageTable_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearPackageTable() {
            this.packageTable_ = emptyProtobufList();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void removePackageTable(int index) {
            ensurePackageTableIsMutable();
            this.packageTable_.remove(index);
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
        public boolean hasStatus() {
            return (this.bitField0_ & 1) == 1;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
        public ResponseStatus getStatus() {
            ResponseStatus result = ResponseStatus.forNumber(this.status_);
            return result == null ? ResponseStatus.SUCCESS : result;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setStatus(ResponseStatus value) {
            if (value == null) {
                throw null;
            }
            this.bitField0_ |= 1;
            this.status_ = value.getNumber();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearStatus() {
            this.bitField0_ &= -2;
            this.status_ = 0;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
        public List<KeyValue> getInternalMetadataList() {
            return this.internalMetadata_;
        }

        public List<? extends KeyValueOrBuilder> getInternalMetadataOrBuilderList() {
            return this.internalMetadata_;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
        public int getInternalMetadataCount() {
            return this.internalMetadata_.size();
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
        public KeyValue getInternalMetadata(int index) {
            return this.internalMetadata_.get(index);
        }

        public KeyValueOrBuilder getInternalMetadataOrBuilder(int index) {
            return this.internalMetadata_.get(index);
        }

        private void ensureInternalMetadataIsMutable() {
            if (!this.internalMetadata_.isModifiable()) {
                this.internalMetadata_ = GeneratedMessageLite.mutableCopy(this.internalMetadata_);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setInternalMetadata(int index, KeyValue value) {
            if (value == null) {
                throw null;
            }
            ensureInternalMetadataIsMutable();
            this.internalMetadata_.set(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setInternalMetadata(int index, KeyValue.Builder builderForValue) {
            ensureInternalMetadataIsMutable();
            this.internalMetadata_.set(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addInternalMetadata(KeyValue value) {
            if (value == null) {
                throw null;
            }
            ensureInternalMetadataIsMutable();
            this.internalMetadata_.add(value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addInternalMetadata(int index, KeyValue value) {
            if (value == null) {
                throw null;
            }
            ensureInternalMetadataIsMutable();
            this.internalMetadata_.add(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addInternalMetadata(KeyValue.Builder builderForValue) {
            ensureInternalMetadataIsMutable();
            this.internalMetadata_.add(builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addInternalMetadata(int index, KeyValue.Builder builderForValue) {
            ensureInternalMetadataIsMutable();
            this.internalMetadata_.add(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAllInternalMetadata(Iterable<? extends KeyValue> values) {
            ensureInternalMetadataIsMutable();
            AbstractMessageLite.addAll(values, this.internalMetadata_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearInternalMetadata() {
            this.internalMetadata_ = emptyProtobufList();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void removeInternalMetadata(int index) {
            ensureInternalMetadataIsMutable();
            this.internalMetadata_.remove(index);
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
        public List<AppConfigTable> getAppConfigList() {
            return this.appConfig_;
        }

        public List<? extends AppConfigTableOrBuilder> getAppConfigOrBuilderList() {
            return this.appConfig_;
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
        public int getAppConfigCount() {
            return this.appConfig_.size();
        }

        @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
        public AppConfigTable getAppConfig(int index) {
            return this.appConfig_.get(index);
        }

        public AppConfigTableOrBuilder getAppConfigOrBuilder(int index) {
            return this.appConfig_.get(index);
        }

        private void ensureAppConfigIsMutable() {
            if (!this.appConfig_.isModifiable()) {
                this.appConfig_ = GeneratedMessageLite.mutableCopy(this.appConfig_);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setAppConfig(int index, AppConfigTable value) {
            if (value == null) {
                throw null;
            }
            ensureAppConfigIsMutable();
            this.appConfig_.set(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setAppConfig(int index, AppConfigTable.Builder builderForValue) {
            ensureAppConfigIsMutable();
            this.appConfig_.set(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAppConfig(AppConfigTable value) {
            if (value == null) {
                throw null;
            }
            ensureAppConfigIsMutable();
            this.appConfig_.add(value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAppConfig(int index, AppConfigTable value) {
            if (value == null) {
                throw null;
            }
            ensureAppConfigIsMutable();
            this.appConfig_.add(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAppConfig(AppConfigTable.Builder builderForValue) {
            ensureAppConfigIsMutable();
            this.appConfig_.add(builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAppConfig(int index, AppConfigTable.Builder builderForValue) {
            ensureAppConfigIsMutable();
            this.appConfig_.add(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAllAppConfig(Iterable<? extends AppConfigTable> values) {
            ensureAppConfigIsMutable();
            AbstractMessageLite.addAll(values, this.appConfig_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearAppConfig() {
            this.appConfig_ = emptyProtobufList();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void removeAppConfig(int index) {
            ensureAppConfigIsMutable();
            this.appConfig_.remove(index);
        }

        @Override // com.google.protobuf.MessageLite
        public void writeTo(CodedOutputStream output) throws IOException {
            for (int i = 0; i < this.packageTable_.size(); i++) {
                output.writeMessage(1, this.packageTable_.get(i));
            }
            int i2 = this.bitField0_;
            if ((i2 & 1) == 1) {
                output.writeEnum(2, this.status_);
            }
            for (int i3 = 0; i3 < this.internalMetadata_.size(); i3++) {
                output.writeMessage(3, this.internalMetadata_.get(i3));
            }
            for (int i4 = 0; i4 < this.appConfig_.size(); i4++) {
                output.writeMessage(4, this.appConfig_.get(i4));
            }
            this.unknownFields.writeTo(output);
        }

        @Override // com.google.protobuf.MessageLite
        public int getSerializedSize() {
            int size = this.memoizedSerializedSize;
            if (size != -1) {
                return size;
            }
            int size2 = 0;
            for (int i = 0; i < this.packageTable_.size(); i++) {
                size2 += CodedOutputStream.computeMessageSize(1, this.packageTable_.get(i));
            }
            int i2 = this.bitField0_;
            if ((i2 & 1) == 1) {
                size2 += CodedOutputStream.computeEnumSize(2, this.status_);
            }
            for (int i3 = 0; i3 < this.internalMetadata_.size(); i3++) {
                size2 += CodedOutputStream.computeMessageSize(3, this.internalMetadata_.get(i3));
            }
            for (int i4 = 0; i4 < this.appConfig_.size(); i4++) {
                size2 += CodedOutputStream.computeMessageSize(4, this.appConfig_.get(i4));
            }
            int size3 = size2 + this.unknownFields.getSerializedSize();
            this.memoizedSerializedSize = size3;
            return size3;
        }

        public static ConfigFetchResponse parseFrom(ByteString data) throws InvalidProtocolBufferException {
            return (ConfigFetchResponse) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static ConfigFetchResponse parseFrom(ByteString data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (ConfigFetchResponse) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static ConfigFetchResponse parseFrom(byte[] data) throws InvalidProtocolBufferException {
            return (ConfigFetchResponse) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static ConfigFetchResponse parseFrom(byte[] data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (ConfigFetchResponse) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static ConfigFetchResponse parseFrom(InputStream input) throws IOException {
            return (ConfigFetchResponse) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static ConfigFetchResponse parseFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (ConfigFetchResponse) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static ConfigFetchResponse parseDelimitedFrom(InputStream input) throws IOException {
            return (ConfigFetchResponse) parseDelimitedFrom(DEFAULT_INSTANCE, input);
        }

        public static ConfigFetchResponse parseDelimitedFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (ConfigFetchResponse) parseDelimitedFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static ConfigFetchResponse parseFrom(CodedInputStream input) throws IOException {
            return (ConfigFetchResponse) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static ConfigFetchResponse parseFrom(CodedInputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (ConfigFetchResponse) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static Builder newBuilder() {
            return DEFAULT_INSTANCE.toBuilder();
        }

        public static Builder newBuilder(ConfigFetchResponse prototype) {
            return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
        }

        /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
        public static final class Builder extends GeneratedMessageLite.Builder<ConfigFetchResponse, Builder> implements ConfigFetchResponseOrBuilder {
            /* synthetic */ Builder(AnonymousClass1 x0) {
                this();
            }

            private Builder() {
                super(ConfigFetchResponse.DEFAULT_INSTANCE);
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
            public List<PackageTable> getPackageTableList() {
                return Collections.unmodifiableList(((ConfigFetchResponse) this.instance).getPackageTableList());
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
            public int getPackageTableCount() {
                return ((ConfigFetchResponse) this.instance).getPackageTableCount();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
            public PackageTable getPackageTable(int index) {
                return ((ConfigFetchResponse) this.instance).getPackageTable(index);
            }

            public Builder setPackageTable(int index, PackageTable value) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).setPackageTable(index, value);
                return this;
            }

            public Builder setPackageTable(int index, PackageTable.Builder builderForValue) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).setPackageTable(index, builderForValue);
                return this;
            }

            public Builder addPackageTable(PackageTable value) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).addPackageTable(value);
                return this;
            }

            public Builder addPackageTable(int index, PackageTable value) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).addPackageTable(index, value);
                return this;
            }

            public Builder addPackageTable(PackageTable.Builder builderForValue) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).addPackageTable(builderForValue);
                return this;
            }

            public Builder addPackageTable(int index, PackageTable.Builder builderForValue) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).addPackageTable(index, builderForValue);
                return this;
            }

            public Builder addAllPackageTable(Iterable<? extends PackageTable> values) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).addAllPackageTable(values);
                return this;
            }

            public Builder clearPackageTable() {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).clearPackageTable();
                return this;
            }

            public Builder removePackageTable(int index) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).removePackageTable(index);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
            public boolean hasStatus() {
                return ((ConfigFetchResponse) this.instance).hasStatus();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
            public ResponseStatus getStatus() {
                return ((ConfigFetchResponse) this.instance).getStatus();
            }

            public Builder setStatus(ResponseStatus value) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).setStatus(value);
                return this;
            }

            public Builder clearStatus() {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).clearStatus();
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
            public List<KeyValue> getInternalMetadataList() {
                return Collections.unmodifiableList(((ConfigFetchResponse) this.instance).getInternalMetadataList());
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
            public int getInternalMetadataCount() {
                return ((ConfigFetchResponse) this.instance).getInternalMetadataCount();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
            public KeyValue getInternalMetadata(int index) {
                return ((ConfigFetchResponse) this.instance).getInternalMetadata(index);
            }

            public Builder setInternalMetadata(int index, KeyValue value) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).setInternalMetadata(index, value);
                return this;
            }

            public Builder setInternalMetadata(int index, KeyValue.Builder builderForValue) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).setInternalMetadata(index, builderForValue);
                return this;
            }

            public Builder addInternalMetadata(KeyValue value) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).addInternalMetadata(value);
                return this;
            }

            public Builder addInternalMetadata(int index, KeyValue value) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).addInternalMetadata(index, value);
                return this;
            }

            public Builder addInternalMetadata(KeyValue.Builder builderForValue) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).addInternalMetadata(builderForValue);
                return this;
            }

            public Builder addInternalMetadata(int index, KeyValue.Builder builderForValue) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).addInternalMetadata(index, builderForValue);
                return this;
            }

            public Builder addAllInternalMetadata(Iterable<? extends KeyValue> values) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).addAllInternalMetadata(values);
                return this;
            }

            public Builder clearInternalMetadata() {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).clearInternalMetadata();
                return this;
            }

            public Builder removeInternalMetadata(int index) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).removeInternalMetadata(index);
                return this;
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
            public List<AppConfigTable> getAppConfigList() {
                return Collections.unmodifiableList(((ConfigFetchResponse) this.instance).getAppConfigList());
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
            public int getAppConfigCount() {
                return ((ConfigFetchResponse) this.instance).getAppConfigCount();
            }

            @Override // com.google.android.gms.config.proto.Config.ConfigFetchResponseOrBuilder
            public AppConfigTable getAppConfig(int index) {
                return ((ConfigFetchResponse) this.instance).getAppConfig(index);
            }

            public Builder setAppConfig(int index, AppConfigTable value) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).setAppConfig(index, value);
                return this;
            }

            public Builder setAppConfig(int index, AppConfigTable.Builder builderForValue) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).setAppConfig(index, builderForValue);
                return this;
            }

            public Builder addAppConfig(AppConfigTable value) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).addAppConfig(value);
                return this;
            }

            public Builder addAppConfig(int index, AppConfigTable value) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).addAppConfig(index, value);
                return this;
            }

            public Builder addAppConfig(AppConfigTable.Builder builderForValue) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).addAppConfig(builderForValue);
                return this;
            }

            public Builder addAppConfig(int index, AppConfigTable.Builder builderForValue) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).addAppConfig(index, builderForValue);
                return this;
            }

            public Builder addAllAppConfig(Iterable<? extends AppConfigTable> values) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).addAllAppConfig(values);
                return this;
            }

            public Builder clearAppConfig() {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).clearAppConfig();
                return this;
            }

            public Builder removeAppConfig(int index) {
                copyOnWrite();
                ((ConfigFetchResponse) this.instance).removeAppConfig(index);
                return this;
            }
        }

        @Override // com.google.protobuf.GeneratedMessageLite
        protected final Object dynamicMethod(GeneratedMessageLite.MethodToInvoke method, Object arg0, Object arg1) {
            AnonymousClass1 anonymousClass1 = null;
            switch (AnonymousClass1.$SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[method.ordinal()]) {
                case 1:
                    return new ConfigFetchResponse();
                case 2:
                    return DEFAULT_INSTANCE;
                case 3:
                    this.packageTable_.makeImmutable();
                    this.internalMetadata_.makeImmutable();
                    this.appConfig_.makeImmutable();
                    return null;
                case 4:
                    return new Builder(anonymousClass1);
                case 5:
                    GeneratedMessageLite.Visitor visitor = (GeneratedMessageLite.Visitor) arg0;
                    ConfigFetchResponse other = (ConfigFetchResponse) arg1;
                    this.packageTable_ = visitor.visitList(this.packageTable_, other.packageTable_);
                    this.status_ = visitor.visitInt(hasStatus(), this.status_, other.hasStatus(), other.status_);
                    this.internalMetadata_ = visitor.visitList(this.internalMetadata_, other.internalMetadata_);
                    this.appConfig_ = visitor.visitList(this.appConfig_, other.appConfig_);
                    if (visitor == GeneratedMessageLite.MergeFromVisitor.INSTANCE) {
                        this.bitField0_ |= other.bitField0_;
                    }
                    return this;
                case 6:
                    CodedInputStream input = (CodedInputStream) arg0;
                    ExtensionRegistryLite extensionRegistry = (ExtensionRegistryLite) arg1;
                    boolean done = false;
                    while (!done) {
                        try {
                            int tag = input.readTag();
                            if (tag == 0) {
                                done = true;
                            } else if (tag == 10) {
                                if (!this.packageTable_.isModifiable()) {
                                    this.packageTable_ = GeneratedMessageLite.mutableCopy(this.packageTable_);
                                }
                                this.packageTable_.add((PackageTable) input.readMessage(PackageTable.parser(), extensionRegistry));
                            } else if (tag == 16) {
                                int rawValue = input.readEnum();
                                ResponseStatus value = ResponseStatus.forNumber(rawValue);
                                if (value == null) {
                                    super.mergeVarintField(2, rawValue);
                                } else {
                                    this.bitField0_ |= 1;
                                    this.status_ = rawValue;
                                }
                            } else if (tag == 26) {
                                if (!this.internalMetadata_.isModifiable()) {
                                    this.internalMetadata_ = GeneratedMessageLite.mutableCopy(this.internalMetadata_);
                                }
                                this.internalMetadata_.add((KeyValue) input.readMessage(KeyValue.parser(), extensionRegistry));
                            } else if (tag != 34) {
                                if (!parseUnknownField(tag, input)) {
                                    done = true;
                                }
                            } else {
                                if (!this.appConfig_.isModifiable()) {
                                    this.appConfig_ = GeneratedMessageLite.mutableCopy(this.appConfig_);
                                }
                                this.appConfig_.add((AppConfigTable) input.readMessage(AppConfigTable.parser(), extensionRegistry));
                            }
                        } catch (InvalidProtocolBufferException e) {
                            throw new RuntimeException(e.setUnfinishedMessage(this));
                        } catch (IOException e2) {
                            throw new RuntimeException(new InvalidProtocolBufferException(e2.getMessage()).setUnfinishedMessage(this));
                        }
                    }
                    break;
                case 7:
                    break;
                case 8:
                    if (PARSER == null) {
                        synchronized (ConfigFetchResponse.class) {
                            if (PARSER == null) {
                                PARSER = new GeneratedMessageLite.DefaultInstanceBasedParser(DEFAULT_INSTANCE);
                            }
                            break;
                        }
                    }
                    return PARSER;
                default:
                    throw new UnsupportedOperationException();
            }
            return DEFAULT_INSTANCE;
        }

        static {
            ConfigFetchResponse configFetchResponse = new ConfigFetchResponse();
            DEFAULT_INSTANCE = configFetchResponse;
            configFetchResponse.makeImmutable();
        }

        public static ConfigFetchResponse getDefaultInstance() {
            return DEFAULT_INSTANCE;
        }

        public static Parser<ConfigFetchResponse> parser() {
            return DEFAULT_INSTANCE.getParserForType();
        }
    }
}
