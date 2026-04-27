package developers.mobile.abt;

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

/* JADX INFO: compiled from: com.google.firebase:firebase-abt@@19.0.0 */
/* JADX INFO: loaded from: classes3.dex */
public final class FirebaseAbt {

    /* JADX INFO: compiled from: com.google.firebase:firebase-abt@@19.0.0 */
    public interface ExperimentLiteOrBuilder extends MessageLiteOrBuilder {
        String getExperimentId();

        ByteString getExperimentIdBytes();
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-abt@@19.0.0 */
    public interface ExperimentPayloadOrBuilder extends MessageLiteOrBuilder {
        String getActivateEventToLog();

        ByteString getActivateEventToLogBytes();

        String getClearEventToLog();

        ByteString getClearEventToLogBytes();

        String getExperimentId();

        ByteString getExperimentIdBytes();

        long getExperimentStartTimeMillis();

        ExperimentLite getOngoingExperiments(int i);

        int getOngoingExperimentsCount();

        List<ExperimentLite> getOngoingExperimentsList();

        ExperimentPayload.ExperimentOverflowPolicy getOverflowPolicy();

        int getOverflowPolicyValue();

        String getSetEventToLog();

        ByteString getSetEventToLogBytes();

        long getTimeToLiveMillis();

        String getTimeoutEventToLog();

        ByteString getTimeoutEventToLogBytes();

        String getTriggerEvent();

        ByteString getTriggerEventBytes();

        long getTriggerTimeoutMillis();

        String getTtlExpiryEventToLog();

        ByteString getTtlExpiryEventToLogBytes();

        String getVariantId();

        ByteString getVariantIdBytes();
    }

    private FirebaseAbt() {
    }

    public static void registerAllExtensions(ExtensionRegistryLite registry) {
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-abt@@19.0.0 */
    public static final class ExperimentLite extends GeneratedMessageLite<ExperimentLite, Builder> implements ExperimentLiteOrBuilder {
        private static final ExperimentLite DEFAULT_INSTANCE;
        public static final int EXPERIMENT_ID_FIELD_NUMBER = 1;
        private static volatile Parser<ExperimentLite> PARSER;
        private String experimentId_ = "";

        private ExperimentLite() {
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentLiteOrBuilder
        public String getExperimentId() {
            return this.experimentId_;
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentLiteOrBuilder
        public ByteString getExperimentIdBytes() {
            return ByteString.copyFromUtf8(this.experimentId_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setExperimentId(String value) {
            if (value == null) {
                throw null;
            }
            this.experimentId_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearExperimentId() {
            this.experimentId_ = getDefaultInstance().getExperimentId();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setExperimentIdBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            checkByteStringIsUtf8(value);
            this.experimentId_ = value.toStringUtf8();
        }

        @Override // com.google.protobuf.MessageLite
        public void writeTo(CodedOutputStream output) throws IOException {
            if (!this.experimentId_.isEmpty()) {
                output.writeString(1, getExperimentId());
            }
        }

        @Override // com.google.protobuf.MessageLite
        public int getSerializedSize() {
            int size = this.memoizedSerializedSize;
            if (size != -1) {
                return size;
            }
            int size2 = this.experimentId_.isEmpty() ? 0 : 0 + CodedOutputStream.computeStringSize(1, getExperimentId());
            this.memoizedSerializedSize = size2;
            return size2;
        }

        public static ExperimentLite parseFrom(ByteString data) throws InvalidProtocolBufferException {
            return (ExperimentLite) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static ExperimentLite parseFrom(ByteString data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (ExperimentLite) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static ExperimentLite parseFrom(byte[] data) throws InvalidProtocolBufferException {
            return (ExperimentLite) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static ExperimentLite parseFrom(byte[] data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (ExperimentLite) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static ExperimentLite parseFrom(InputStream input) throws IOException {
            return (ExperimentLite) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static ExperimentLite parseFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (ExperimentLite) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static ExperimentLite parseDelimitedFrom(InputStream input) throws IOException {
            return (ExperimentLite) parseDelimitedFrom(DEFAULT_INSTANCE, input);
        }

        public static ExperimentLite parseDelimitedFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (ExperimentLite) parseDelimitedFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static ExperimentLite parseFrom(CodedInputStream input) throws IOException {
            return (ExperimentLite) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static ExperimentLite parseFrom(CodedInputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (ExperimentLite) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static Builder newBuilder() {
            return DEFAULT_INSTANCE.toBuilder();
        }

        public static Builder newBuilder(ExperimentLite prototype) {
            return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
        }

        /* JADX INFO: compiled from: com.google.firebase:firebase-abt@@19.0.0 */
        public static final class Builder extends GeneratedMessageLite.Builder<ExperimentLite, Builder> implements ExperimentLiteOrBuilder {
            /* synthetic */ Builder(AnonymousClass1 x0) {
                this();
            }

            private Builder() {
                super(ExperimentLite.DEFAULT_INSTANCE);
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentLiteOrBuilder
            public String getExperimentId() {
                return ((ExperimentLite) this.instance).getExperimentId();
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentLiteOrBuilder
            public ByteString getExperimentIdBytes() {
                return ((ExperimentLite) this.instance).getExperimentIdBytes();
            }

            public Builder setExperimentId(String value) {
                copyOnWrite();
                ((ExperimentLite) this.instance).setExperimentId(value);
                return this;
            }

            public Builder clearExperimentId() {
                copyOnWrite();
                ((ExperimentLite) this.instance).clearExperimentId();
                return this;
            }

            public Builder setExperimentIdBytes(ByteString value) {
                copyOnWrite();
                ((ExperimentLite) this.instance).setExperimentIdBytes(value);
                return this;
            }
        }

        @Override // com.google.protobuf.GeneratedMessageLite
        protected final Object dynamicMethod(GeneratedMessageLite.MethodToInvoke method, Object arg0, Object arg1) {
            AnonymousClass1 anonymousClass1 = null;
            switch (AnonymousClass1.$SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[method.ordinal()]) {
                case 1:
                    return new ExperimentLite();
                case 2:
                    return DEFAULT_INSTANCE;
                case 3:
                    return null;
                case 4:
                    return new Builder(anonymousClass1);
                case 5:
                    GeneratedMessageLite.Visitor visitor = (GeneratedMessageLite.Visitor) arg0;
                    ExperimentLite other = (ExperimentLite) arg1;
                    this.experimentId_ = visitor.visitString(!this.experimentId_.isEmpty(), this.experimentId_, !other.experimentId_.isEmpty(), other.experimentId_);
                    GeneratedMessageLite.MergeFromVisitor mergeFromVisitor = GeneratedMessageLite.MergeFromVisitor.INSTANCE;
                    return this;
                case 6:
                    CodedInputStream input = (CodedInputStream) arg0;
                    boolean done = false;
                    while (!done) {
                        try {
                            try {
                                int tag = input.readTag();
                                if (tag == 0) {
                                    done = true;
                                } else if (tag != 10) {
                                    if (!input.skipField(tag)) {
                                        done = true;
                                    }
                                } else {
                                    String s = input.readStringRequireUtf8();
                                    this.experimentId_ = s;
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
                        synchronized (ExperimentLite.class) {
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
            ExperimentLite experimentLite = new ExperimentLite();
            DEFAULT_INSTANCE = experimentLite;
            experimentLite.makeImmutable();
        }

        public static ExperimentLite getDefaultInstance() {
            return DEFAULT_INSTANCE;
        }

        public static Parser<ExperimentLite> parser() {
            return DEFAULT_INSTANCE.getParserForType();
        }
    }

    /* JADX INFO: renamed from: developers.mobile.abt.FirebaseAbt$1, reason: invalid class name */
    /* JADX INFO: compiled from: com.google.firebase:firebase-abt@@19.0.0 */
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

    /* JADX INFO: compiled from: com.google.firebase:firebase-abt@@19.0.0 */
    public static final class ExperimentPayload extends GeneratedMessageLite<ExperimentPayload, Builder> implements ExperimentPayloadOrBuilder {
        public static final int ACTIVATE_EVENT_TO_LOG_FIELD_NUMBER = 8;
        public static final int CLEAR_EVENT_TO_LOG_FIELD_NUMBER = 9;
        private static final ExperimentPayload DEFAULT_INSTANCE;
        public static final int EXPERIMENT_ID_FIELD_NUMBER = 1;
        public static final int EXPERIMENT_START_TIME_MILLIS_FIELD_NUMBER = 3;
        public static final int ONGOING_EXPERIMENTS_FIELD_NUMBER = 13;
        public static final int OVERFLOW_POLICY_FIELD_NUMBER = 12;
        private static volatile Parser<ExperimentPayload> PARSER = null;
        public static final int SET_EVENT_TO_LOG_FIELD_NUMBER = 7;
        public static final int TIMEOUT_EVENT_TO_LOG_FIELD_NUMBER = 10;
        public static final int TIME_TO_LIVE_MILLIS_FIELD_NUMBER = 6;
        public static final int TRIGGER_EVENT_FIELD_NUMBER = 4;
        public static final int TRIGGER_TIMEOUT_MILLIS_FIELD_NUMBER = 5;
        public static final int TTL_EXPIRY_EVENT_TO_LOG_FIELD_NUMBER = 11;
        public static final int VARIANT_ID_FIELD_NUMBER = 2;
        private int bitField0_;
        private long experimentStartTimeMillis_;
        private int overflowPolicy_;
        private long timeToLiveMillis_;
        private long triggerTimeoutMillis_;
        private String experimentId_ = "";
        private String variantId_ = "";
        private String triggerEvent_ = "";
        private String setEventToLog_ = "";
        private String activateEventToLog_ = "";
        private String clearEventToLog_ = "";
        private String timeoutEventToLog_ = "";
        private String ttlExpiryEventToLog_ = "";
        private Internal.ProtobufList<ExperimentLite> ongoingExperiments_ = emptyProtobufList();

        private ExperimentPayload() {
        }

        /* JADX INFO: compiled from: com.google.firebase:firebase-abt@@19.0.0 */
        public enum ExperimentOverflowPolicy implements Internal.EnumLite {
            POLICY_UNSPECIFIED(0),
            DISCARD_OLDEST(1),
            IGNORE_NEWEST(2),
            UNRECOGNIZED(-1);

            public static final int DISCARD_OLDEST_VALUE = 1;
            public static final int IGNORE_NEWEST_VALUE = 2;
            public static final int POLICY_UNSPECIFIED_VALUE = 0;
            private static final Internal.EnumLiteMap<ExperimentOverflowPolicy> internalValueMap = new Internal.EnumLiteMap<ExperimentOverflowPolicy>() { // from class: developers.mobile.abt.FirebaseAbt.ExperimentPayload.ExperimentOverflowPolicy.1
                @Override // com.google.protobuf.Internal.EnumLiteMap
                public ExperimentOverflowPolicy findValueByNumber(int number) {
                    return ExperimentOverflowPolicy.forNumber(number);
                }
            };
            private final int value;

            @Override // com.google.protobuf.Internal.EnumLite
            public final int getNumber() {
                return this.value;
            }

            @Deprecated
            public static ExperimentOverflowPolicy valueOf(int value) {
                return forNumber(value);
            }

            public static ExperimentOverflowPolicy forNumber(int value) {
                if (value == 0) {
                    return POLICY_UNSPECIFIED;
                }
                if (value == 1) {
                    return DISCARD_OLDEST;
                }
                if (value == 2) {
                    return IGNORE_NEWEST;
                }
                return null;
            }

            public static Internal.EnumLiteMap<ExperimentOverflowPolicy> internalGetValueMap() {
                return internalValueMap;
            }

            ExperimentOverflowPolicy(int value) {
                this.value = value;
            }
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public String getExperimentId() {
            return this.experimentId_;
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public ByteString getExperimentIdBytes() {
            return ByteString.copyFromUtf8(this.experimentId_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setExperimentId(String value) {
            if (value == null) {
                throw null;
            }
            this.experimentId_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearExperimentId() {
            this.experimentId_ = getDefaultInstance().getExperimentId();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setExperimentIdBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            checkByteStringIsUtf8(value);
            this.experimentId_ = value.toStringUtf8();
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public String getVariantId() {
            return this.variantId_;
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public ByteString getVariantIdBytes() {
            return ByteString.copyFromUtf8(this.variantId_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setVariantId(String value) {
            if (value == null) {
                throw null;
            }
            this.variantId_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearVariantId() {
            this.variantId_ = getDefaultInstance().getVariantId();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setVariantIdBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            checkByteStringIsUtf8(value);
            this.variantId_ = value.toStringUtf8();
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public long getExperimentStartTimeMillis() {
            return this.experimentStartTimeMillis_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setExperimentStartTimeMillis(long value) {
            this.experimentStartTimeMillis_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearExperimentStartTimeMillis() {
            this.experimentStartTimeMillis_ = 0L;
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public String getTriggerEvent() {
            return this.triggerEvent_;
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public ByteString getTriggerEventBytes() {
            return ByteString.copyFromUtf8(this.triggerEvent_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setTriggerEvent(String value) {
            if (value == null) {
                throw null;
            }
            this.triggerEvent_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearTriggerEvent() {
            this.triggerEvent_ = getDefaultInstance().getTriggerEvent();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setTriggerEventBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            checkByteStringIsUtf8(value);
            this.triggerEvent_ = value.toStringUtf8();
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public long getTriggerTimeoutMillis() {
            return this.triggerTimeoutMillis_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setTriggerTimeoutMillis(long value) {
            this.triggerTimeoutMillis_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearTriggerTimeoutMillis() {
            this.triggerTimeoutMillis_ = 0L;
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public long getTimeToLiveMillis() {
            return this.timeToLiveMillis_;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setTimeToLiveMillis(long value) {
            this.timeToLiveMillis_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearTimeToLiveMillis() {
            this.timeToLiveMillis_ = 0L;
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public String getSetEventToLog() {
            return this.setEventToLog_;
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public ByteString getSetEventToLogBytes() {
            return ByteString.copyFromUtf8(this.setEventToLog_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setSetEventToLog(String value) {
            if (value == null) {
                throw null;
            }
            this.setEventToLog_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearSetEventToLog() {
            this.setEventToLog_ = getDefaultInstance().getSetEventToLog();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setSetEventToLogBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            checkByteStringIsUtf8(value);
            this.setEventToLog_ = value.toStringUtf8();
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public String getActivateEventToLog() {
            return this.activateEventToLog_;
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public ByteString getActivateEventToLogBytes() {
            return ByteString.copyFromUtf8(this.activateEventToLog_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setActivateEventToLog(String value) {
            if (value == null) {
                throw null;
            }
            this.activateEventToLog_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearActivateEventToLog() {
            this.activateEventToLog_ = getDefaultInstance().getActivateEventToLog();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setActivateEventToLogBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            checkByteStringIsUtf8(value);
            this.activateEventToLog_ = value.toStringUtf8();
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public String getClearEventToLog() {
            return this.clearEventToLog_;
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public ByteString getClearEventToLogBytes() {
            return ByteString.copyFromUtf8(this.clearEventToLog_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setClearEventToLog(String value) {
            if (value == null) {
                throw null;
            }
            this.clearEventToLog_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearClearEventToLog() {
            this.clearEventToLog_ = getDefaultInstance().getClearEventToLog();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setClearEventToLogBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            checkByteStringIsUtf8(value);
            this.clearEventToLog_ = value.toStringUtf8();
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public String getTimeoutEventToLog() {
            return this.timeoutEventToLog_;
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public ByteString getTimeoutEventToLogBytes() {
            return ByteString.copyFromUtf8(this.timeoutEventToLog_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setTimeoutEventToLog(String value) {
            if (value == null) {
                throw null;
            }
            this.timeoutEventToLog_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearTimeoutEventToLog() {
            this.timeoutEventToLog_ = getDefaultInstance().getTimeoutEventToLog();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setTimeoutEventToLogBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            checkByteStringIsUtf8(value);
            this.timeoutEventToLog_ = value.toStringUtf8();
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public String getTtlExpiryEventToLog() {
            return this.ttlExpiryEventToLog_;
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public ByteString getTtlExpiryEventToLogBytes() {
            return ByteString.copyFromUtf8(this.ttlExpiryEventToLog_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setTtlExpiryEventToLog(String value) {
            if (value == null) {
                throw null;
            }
            this.ttlExpiryEventToLog_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearTtlExpiryEventToLog() {
            this.ttlExpiryEventToLog_ = getDefaultInstance().getTtlExpiryEventToLog();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setTtlExpiryEventToLogBytes(ByteString value) {
            if (value == null) {
                throw null;
            }
            checkByteStringIsUtf8(value);
            this.ttlExpiryEventToLog_ = value.toStringUtf8();
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public int getOverflowPolicyValue() {
            return this.overflowPolicy_;
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public ExperimentOverflowPolicy getOverflowPolicy() {
            ExperimentOverflowPolicy result = ExperimentOverflowPolicy.forNumber(this.overflowPolicy_);
            return result == null ? ExperimentOverflowPolicy.UNRECOGNIZED : result;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setOverflowPolicyValue(int value) {
            this.overflowPolicy_ = value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setOverflowPolicy(ExperimentOverflowPolicy value) {
            if (value == null) {
                throw null;
            }
            this.overflowPolicy_ = value.getNumber();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearOverflowPolicy() {
            this.overflowPolicy_ = 0;
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public List<ExperimentLite> getOngoingExperimentsList() {
            return this.ongoingExperiments_;
        }

        public List<? extends ExperimentLiteOrBuilder> getOngoingExperimentsOrBuilderList() {
            return this.ongoingExperiments_;
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public int getOngoingExperimentsCount() {
            return this.ongoingExperiments_.size();
        }

        @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
        public ExperimentLite getOngoingExperiments(int index) {
            return this.ongoingExperiments_.get(index);
        }

        public ExperimentLiteOrBuilder getOngoingExperimentsOrBuilder(int index) {
            return this.ongoingExperiments_.get(index);
        }

        private void ensureOngoingExperimentsIsMutable() {
            if (!this.ongoingExperiments_.isModifiable()) {
                this.ongoingExperiments_ = GeneratedMessageLite.mutableCopy(this.ongoingExperiments_);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setOngoingExperiments(int index, ExperimentLite value) {
            if (value == null) {
                throw null;
            }
            ensureOngoingExperimentsIsMutable();
            this.ongoingExperiments_.set(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setOngoingExperiments(int index, ExperimentLite.Builder builderForValue) {
            ensureOngoingExperimentsIsMutable();
            this.ongoingExperiments_.set(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addOngoingExperiments(ExperimentLite value) {
            if (value == null) {
                throw null;
            }
            ensureOngoingExperimentsIsMutable();
            this.ongoingExperiments_.add(value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addOngoingExperiments(int index, ExperimentLite value) {
            if (value == null) {
                throw null;
            }
            ensureOngoingExperimentsIsMutable();
            this.ongoingExperiments_.add(index, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addOngoingExperiments(ExperimentLite.Builder builderForValue) {
            ensureOngoingExperimentsIsMutable();
            this.ongoingExperiments_.add(builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addOngoingExperiments(int index, ExperimentLite.Builder builderForValue) {
            ensureOngoingExperimentsIsMutable();
            this.ongoingExperiments_.add(index, builderForValue.build());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addAllOngoingExperiments(Iterable<? extends ExperimentLite> values) {
            ensureOngoingExperimentsIsMutable();
            AbstractMessageLite.addAll(values, this.ongoingExperiments_);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearOngoingExperiments() {
            this.ongoingExperiments_ = emptyProtobufList();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void removeOngoingExperiments(int index) {
            ensureOngoingExperimentsIsMutable();
            this.ongoingExperiments_.remove(index);
        }

        @Override // com.google.protobuf.MessageLite
        public void writeTo(CodedOutputStream output) throws IOException {
            if (!this.experimentId_.isEmpty()) {
                output.writeString(1, getExperimentId());
            }
            if (!this.variantId_.isEmpty()) {
                output.writeString(2, getVariantId());
            }
            long j = this.experimentStartTimeMillis_;
            if (j != 0) {
                output.writeInt64(3, j);
            }
            if (!this.triggerEvent_.isEmpty()) {
                output.writeString(4, getTriggerEvent());
            }
            long j2 = this.triggerTimeoutMillis_;
            if (j2 != 0) {
                output.writeInt64(5, j2);
            }
            long j3 = this.timeToLiveMillis_;
            if (j3 != 0) {
                output.writeInt64(6, j3);
            }
            if (!this.setEventToLog_.isEmpty()) {
                output.writeString(7, getSetEventToLog());
            }
            if (!this.activateEventToLog_.isEmpty()) {
                output.writeString(8, getActivateEventToLog());
            }
            if (!this.clearEventToLog_.isEmpty()) {
                output.writeString(9, getClearEventToLog());
            }
            if (!this.timeoutEventToLog_.isEmpty()) {
                output.writeString(10, getTimeoutEventToLog());
            }
            if (!this.ttlExpiryEventToLog_.isEmpty()) {
                output.writeString(11, getTtlExpiryEventToLog());
            }
            if (this.overflowPolicy_ != ExperimentOverflowPolicy.POLICY_UNSPECIFIED.getNumber()) {
                output.writeEnum(12, this.overflowPolicy_);
            }
            for (int i = 0; i < this.ongoingExperiments_.size(); i++) {
                output.writeMessage(13, this.ongoingExperiments_.get(i));
            }
        }

        @Override // com.google.protobuf.MessageLite
        public int getSerializedSize() {
            int size = this.memoizedSerializedSize;
            if (size != -1) {
                return size;
            }
            int size2 = this.experimentId_.isEmpty() ? 0 : 0 + CodedOutputStream.computeStringSize(1, getExperimentId());
            if (!this.variantId_.isEmpty()) {
                size2 += CodedOutputStream.computeStringSize(2, getVariantId());
            }
            long j = this.experimentStartTimeMillis_;
            if (j != 0) {
                size2 += CodedOutputStream.computeInt64Size(3, j);
            }
            if (!this.triggerEvent_.isEmpty()) {
                size2 += CodedOutputStream.computeStringSize(4, getTriggerEvent());
            }
            long j2 = this.triggerTimeoutMillis_;
            if (j2 != 0) {
                size2 += CodedOutputStream.computeInt64Size(5, j2);
            }
            long j3 = this.timeToLiveMillis_;
            if (j3 != 0) {
                size2 += CodedOutputStream.computeInt64Size(6, j3);
            }
            if (!this.setEventToLog_.isEmpty()) {
                size2 += CodedOutputStream.computeStringSize(7, getSetEventToLog());
            }
            if (!this.activateEventToLog_.isEmpty()) {
                size2 += CodedOutputStream.computeStringSize(8, getActivateEventToLog());
            }
            if (!this.clearEventToLog_.isEmpty()) {
                size2 += CodedOutputStream.computeStringSize(9, getClearEventToLog());
            }
            if (!this.timeoutEventToLog_.isEmpty()) {
                size2 += CodedOutputStream.computeStringSize(10, getTimeoutEventToLog());
            }
            if (!this.ttlExpiryEventToLog_.isEmpty()) {
                size2 += CodedOutputStream.computeStringSize(11, getTtlExpiryEventToLog());
            }
            if (this.overflowPolicy_ != ExperimentOverflowPolicy.POLICY_UNSPECIFIED.getNumber()) {
                size2 += CodedOutputStream.computeEnumSize(12, this.overflowPolicy_);
            }
            for (int i = 0; i < this.ongoingExperiments_.size(); i++) {
                size2 += CodedOutputStream.computeMessageSize(13, this.ongoingExperiments_.get(i));
            }
            this.memoizedSerializedSize = size2;
            return size2;
        }

        public static ExperimentPayload parseFrom(ByteString data) throws InvalidProtocolBufferException {
            return (ExperimentPayload) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static ExperimentPayload parseFrom(ByteString data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (ExperimentPayload) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static ExperimentPayload parseFrom(byte[] data) throws InvalidProtocolBufferException {
            return (ExperimentPayload) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data);
        }

        public static ExperimentPayload parseFrom(byte[] data, ExtensionRegistryLite extensionRegistry) throws InvalidProtocolBufferException {
            return (ExperimentPayload) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, data, extensionRegistry);
        }

        public static ExperimentPayload parseFrom(InputStream input) throws IOException {
            return (ExperimentPayload) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static ExperimentPayload parseFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (ExperimentPayload) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static ExperimentPayload parseDelimitedFrom(InputStream input) throws IOException {
            return (ExperimentPayload) parseDelimitedFrom(DEFAULT_INSTANCE, input);
        }

        public static ExperimentPayload parseDelimitedFrom(InputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (ExperimentPayload) parseDelimitedFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static ExperimentPayload parseFrom(CodedInputStream input) throws IOException {
            return (ExperimentPayload) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input);
        }

        public static ExperimentPayload parseFrom(CodedInputStream input, ExtensionRegistryLite extensionRegistry) throws IOException {
            return (ExperimentPayload) GeneratedMessageLite.parseFrom(DEFAULT_INSTANCE, input, extensionRegistry);
        }

        public static Builder newBuilder() {
            return DEFAULT_INSTANCE.toBuilder();
        }

        public static Builder newBuilder(ExperimentPayload prototype) {
            return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
        }

        /* JADX INFO: compiled from: com.google.firebase:firebase-abt@@19.0.0 */
        public static final class Builder extends GeneratedMessageLite.Builder<ExperimentPayload, Builder> implements ExperimentPayloadOrBuilder {
            /* synthetic */ Builder(AnonymousClass1 x0) {
                this();
            }

            private Builder() {
                super(ExperimentPayload.DEFAULT_INSTANCE);
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public String getExperimentId() {
                return ((ExperimentPayload) this.instance).getExperimentId();
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public ByteString getExperimentIdBytes() {
                return ((ExperimentPayload) this.instance).getExperimentIdBytes();
            }

            public Builder setExperimentId(String value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setExperimentId(value);
                return this;
            }

            public Builder clearExperimentId() {
                copyOnWrite();
                ((ExperimentPayload) this.instance).clearExperimentId();
                return this;
            }

            public Builder setExperimentIdBytes(ByteString value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setExperimentIdBytes(value);
                return this;
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public String getVariantId() {
                return ((ExperimentPayload) this.instance).getVariantId();
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public ByteString getVariantIdBytes() {
                return ((ExperimentPayload) this.instance).getVariantIdBytes();
            }

            public Builder setVariantId(String value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setVariantId(value);
                return this;
            }

            public Builder clearVariantId() {
                copyOnWrite();
                ((ExperimentPayload) this.instance).clearVariantId();
                return this;
            }

            public Builder setVariantIdBytes(ByteString value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setVariantIdBytes(value);
                return this;
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public long getExperimentStartTimeMillis() {
                return ((ExperimentPayload) this.instance).getExperimentStartTimeMillis();
            }

            public Builder setExperimentStartTimeMillis(long value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setExperimentStartTimeMillis(value);
                return this;
            }

            public Builder clearExperimentStartTimeMillis() {
                copyOnWrite();
                ((ExperimentPayload) this.instance).clearExperimentStartTimeMillis();
                return this;
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public String getTriggerEvent() {
                return ((ExperimentPayload) this.instance).getTriggerEvent();
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public ByteString getTriggerEventBytes() {
                return ((ExperimentPayload) this.instance).getTriggerEventBytes();
            }

            public Builder setTriggerEvent(String value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setTriggerEvent(value);
                return this;
            }

            public Builder clearTriggerEvent() {
                copyOnWrite();
                ((ExperimentPayload) this.instance).clearTriggerEvent();
                return this;
            }

            public Builder setTriggerEventBytes(ByteString value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setTriggerEventBytes(value);
                return this;
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public long getTriggerTimeoutMillis() {
                return ((ExperimentPayload) this.instance).getTriggerTimeoutMillis();
            }

            public Builder setTriggerTimeoutMillis(long value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setTriggerTimeoutMillis(value);
                return this;
            }

            public Builder clearTriggerTimeoutMillis() {
                copyOnWrite();
                ((ExperimentPayload) this.instance).clearTriggerTimeoutMillis();
                return this;
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public long getTimeToLiveMillis() {
                return ((ExperimentPayload) this.instance).getTimeToLiveMillis();
            }

            public Builder setTimeToLiveMillis(long value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setTimeToLiveMillis(value);
                return this;
            }

            public Builder clearTimeToLiveMillis() {
                copyOnWrite();
                ((ExperimentPayload) this.instance).clearTimeToLiveMillis();
                return this;
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public String getSetEventToLog() {
                return ((ExperimentPayload) this.instance).getSetEventToLog();
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public ByteString getSetEventToLogBytes() {
                return ((ExperimentPayload) this.instance).getSetEventToLogBytes();
            }

            public Builder setSetEventToLog(String value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setSetEventToLog(value);
                return this;
            }

            public Builder clearSetEventToLog() {
                copyOnWrite();
                ((ExperimentPayload) this.instance).clearSetEventToLog();
                return this;
            }

            public Builder setSetEventToLogBytes(ByteString value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setSetEventToLogBytes(value);
                return this;
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public String getActivateEventToLog() {
                return ((ExperimentPayload) this.instance).getActivateEventToLog();
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public ByteString getActivateEventToLogBytes() {
                return ((ExperimentPayload) this.instance).getActivateEventToLogBytes();
            }

            public Builder setActivateEventToLog(String value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setActivateEventToLog(value);
                return this;
            }

            public Builder clearActivateEventToLog() {
                copyOnWrite();
                ((ExperimentPayload) this.instance).clearActivateEventToLog();
                return this;
            }

            public Builder setActivateEventToLogBytes(ByteString value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setActivateEventToLogBytes(value);
                return this;
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public String getClearEventToLog() {
                return ((ExperimentPayload) this.instance).getClearEventToLog();
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public ByteString getClearEventToLogBytes() {
                return ((ExperimentPayload) this.instance).getClearEventToLogBytes();
            }

            public Builder setClearEventToLog(String value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setClearEventToLog(value);
                return this;
            }

            public Builder clearClearEventToLog() {
                copyOnWrite();
                ((ExperimentPayload) this.instance).clearClearEventToLog();
                return this;
            }

            public Builder setClearEventToLogBytes(ByteString value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setClearEventToLogBytes(value);
                return this;
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public String getTimeoutEventToLog() {
                return ((ExperimentPayload) this.instance).getTimeoutEventToLog();
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public ByteString getTimeoutEventToLogBytes() {
                return ((ExperimentPayload) this.instance).getTimeoutEventToLogBytes();
            }

            public Builder setTimeoutEventToLog(String value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setTimeoutEventToLog(value);
                return this;
            }

            public Builder clearTimeoutEventToLog() {
                copyOnWrite();
                ((ExperimentPayload) this.instance).clearTimeoutEventToLog();
                return this;
            }

            public Builder setTimeoutEventToLogBytes(ByteString value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setTimeoutEventToLogBytes(value);
                return this;
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public String getTtlExpiryEventToLog() {
                return ((ExperimentPayload) this.instance).getTtlExpiryEventToLog();
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public ByteString getTtlExpiryEventToLogBytes() {
                return ((ExperimentPayload) this.instance).getTtlExpiryEventToLogBytes();
            }

            public Builder setTtlExpiryEventToLog(String value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setTtlExpiryEventToLog(value);
                return this;
            }

            public Builder clearTtlExpiryEventToLog() {
                copyOnWrite();
                ((ExperimentPayload) this.instance).clearTtlExpiryEventToLog();
                return this;
            }

            public Builder setTtlExpiryEventToLogBytes(ByteString value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setTtlExpiryEventToLogBytes(value);
                return this;
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public int getOverflowPolicyValue() {
                return ((ExperimentPayload) this.instance).getOverflowPolicyValue();
            }

            public Builder setOverflowPolicyValue(int value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setOverflowPolicyValue(value);
                return this;
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public ExperimentOverflowPolicy getOverflowPolicy() {
                return ((ExperimentPayload) this.instance).getOverflowPolicy();
            }

            public Builder setOverflowPolicy(ExperimentOverflowPolicy value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setOverflowPolicy(value);
                return this;
            }

            public Builder clearOverflowPolicy() {
                copyOnWrite();
                ((ExperimentPayload) this.instance).clearOverflowPolicy();
                return this;
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public List<ExperimentLite> getOngoingExperimentsList() {
                return Collections.unmodifiableList(((ExperimentPayload) this.instance).getOngoingExperimentsList());
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public int getOngoingExperimentsCount() {
                return ((ExperimentPayload) this.instance).getOngoingExperimentsCount();
            }

            @Override // developers.mobile.abt.FirebaseAbt.ExperimentPayloadOrBuilder
            public ExperimentLite getOngoingExperiments(int index) {
                return ((ExperimentPayload) this.instance).getOngoingExperiments(index);
            }

            public Builder setOngoingExperiments(int index, ExperimentLite value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setOngoingExperiments(index, value);
                return this;
            }

            public Builder setOngoingExperiments(int index, ExperimentLite.Builder builderForValue) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).setOngoingExperiments(index, builderForValue);
                return this;
            }

            public Builder addOngoingExperiments(ExperimentLite value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).addOngoingExperiments(value);
                return this;
            }

            public Builder addOngoingExperiments(int index, ExperimentLite value) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).addOngoingExperiments(index, value);
                return this;
            }

            public Builder addOngoingExperiments(ExperimentLite.Builder builderForValue) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).addOngoingExperiments(builderForValue);
                return this;
            }

            public Builder addOngoingExperiments(int index, ExperimentLite.Builder builderForValue) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).addOngoingExperiments(index, builderForValue);
                return this;
            }

            public Builder addAllOngoingExperiments(Iterable<? extends ExperimentLite> values) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).addAllOngoingExperiments(values);
                return this;
            }

            public Builder clearOngoingExperiments() {
                copyOnWrite();
                ((ExperimentPayload) this.instance).clearOngoingExperiments();
                return this;
            }

            public Builder removeOngoingExperiments(int index) {
                copyOnWrite();
                ((ExperimentPayload) this.instance).removeOngoingExperiments(index);
                return this;
            }
        }

        @Override // com.google.protobuf.GeneratedMessageLite
        protected final Object dynamicMethod(GeneratedMessageLite.MethodToInvoke method, Object arg0, Object arg1) {
            AnonymousClass1 anonymousClass1 = null;
            switch (AnonymousClass1.$SwitchMap$com$google$protobuf$GeneratedMessageLite$MethodToInvoke[method.ordinal()]) {
                case 1:
                    return new ExperimentPayload();
                case 2:
                    return DEFAULT_INSTANCE;
                case 3:
                    this.ongoingExperiments_.makeImmutable();
                    return null;
                case 4:
                    return new Builder(anonymousClass1);
                case 5:
                    GeneratedMessageLite.Visitor visitor = (GeneratedMessageLite.Visitor) arg0;
                    ExperimentPayload other = (ExperimentPayload) arg1;
                    this.experimentId_ = visitor.visitString(!this.experimentId_.isEmpty(), this.experimentId_, !other.experimentId_.isEmpty(), other.experimentId_);
                    this.variantId_ = visitor.visitString(!this.variantId_.isEmpty(), this.variantId_, !other.variantId_.isEmpty(), other.variantId_);
                    this.experimentStartTimeMillis_ = visitor.visitLong(this.experimentStartTimeMillis_ != 0, this.experimentStartTimeMillis_, other.experimentStartTimeMillis_ != 0, other.experimentStartTimeMillis_);
                    this.triggerEvent_ = visitor.visitString(!this.triggerEvent_.isEmpty(), this.triggerEvent_, !other.triggerEvent_.isEmpty(), other.triggerEvent_);
                    this.triggerTimeoutMillis_ = visitor.visitLong(this.triggerTimeoutMillis_ != 0, this.triggerTimeoutMillis_, other.triggerTimeoutMillis_ != 0, other.triggerTimeoutMillis_);
                    this.timeToLiveMillis_ = visitor.visitLong(this.timeToLiveMillis_ != 0, this.timeToLiveMillis_, other.timeToLiveMillis_ != 0, other.timeToLiveMillis_);
                    this.setEventToLog_ = visitor.visitString(!this.setEventToLog_.isEmpty(), this.setEventToLog_, !other.setEventToLog_.isEmpty(), other.setEventToLog_);
                    this.activateEventToLog_ = visitor.visitString(!this.activateEventToLog_.isEmpty(), this.activateEventToLog_, !other.activateEventToLog_.isEmpty(), other.activateEventToLog_);
                    this.clearEventToLog_ = visitor.visitString(!this.clearEventToLog_.isEmpty(), this.clearEventToLog_, !other.clearEventToLog_.isEmpty(), other.clearEventToLog_);
                    this.timeoutEventToLog_ = visitor.visitString(!this.timeoutEventToLog_.isEmpty(), this.timeoutEventToLog_, !other.timeoutEventToLog_.isEmpty(), other.timeoutEventToLog_);
                    this.ttlExpiryEventToLog_ = visitor.visitString(!this.ttlExpiryEventToLog_.isEmpty(), this.ttlExpiryEventToLog_, !other.ttlExpiryEventToLog_.isEmpty(), other.ttlExpiryEventToLog_);
                    this.overflowPolicy_ = visitor.visitInt(this.overflowPolicy_ != 0, this.overflowPolicy_, other.overflowPolicy_ != 0, other.overflowPolicy_);
                    this.ongoingExperiments_ = visitor.visitList(this.ongoingExperiments_, other.ongoingExperiments_);
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
                                case 10:
                                    String s = input.readStringRequireUtf8();
                                    this.experimentId_ = s;
                                    break;
                                case 18:
                                    String s2 = input.readStringRequireUtf8();
                                    this.variantId_ = s2;
                                    break;
                                case 24:
                                    this.experimentStartTimeMillis_ = input.readInt64();
                                    break;
                                case 34:
                                    String s3 = input.readStringRequireUtf8();
                                    this.triggerEvent_ = s3;
                                    break;
                                case 40:
                                    this.triggerTimeoutMillis_ = input.readInt64();
                                    break;
                                case 48:
                                    this.timeToLiveMillis_ = input.readInt64();
                                    break;
                                case 58:
                                    String s4 = input.readStringRequireUtf8();
                                    this.setEventToLog_ = s4;
                                    break;
                                case 66:
                                    String s5 = input.readStringRequireUtf8();
                                    this.activateEventToLog_ = s5;
                                    break;
                                case 74:
                                    String s6 = input.readStringRequireUtf8();
                                    this.clearEventToLog_ = s6;
                                    break;
                                case 82:
                                    String s7 = input.readStringRequireUtf8();
                                    this.timeoutEventToLog_ = s7;
                                    break;
                                case 90:
                                    String s8 = input.readStringRequireUtf8();
                                    this.ttlExpiryEventToLog_ = s8;
                                    break;
                                case 96:
                                    int rawValue = input.readEnum();
                                    this.overflowPolicy_ = rawValue;
                                    break;
                                case 106:
                                    if (!this.ongoingExperiments_.isModifiable()) {
                                        this.ongoingExperiments_ = GeneratedMessageLite.mutableCopy(this.ongoingExperiments_);
                                    }
                                    this.ongoingExperiments_.add((ExperimentLite) input.readMessage(ExperimentLite.parser(), extensionRegistry));
                                    break;
                                default:
                                    if (!input.skipField(tag)) {
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
                        synchronized (ExperimentPayload.class) {
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
            ExperimentPayload experimentPayload = new ExperimentPayload();
            DEFAULT_INSTANCE = experimentPayload;
            experimentPayload.makeImmutable();
        }

        public static ExperimentPayload getDefaultInstance() {
            return DEFAULT_INSTANCE;
        }

        public static Parser<ExperimentPayload> parser() {
            return DEFAULT_INSTANCE.getParserForType();
        }
    }
}
