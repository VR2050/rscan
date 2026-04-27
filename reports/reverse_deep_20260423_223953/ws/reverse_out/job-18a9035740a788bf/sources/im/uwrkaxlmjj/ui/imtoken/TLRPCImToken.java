package im.uwrkaxlmjj.ui.imtoken;

import im.uwrkaxlmjj.tgnet.AbstractSerializedData;
import im.uwrkaxlmjj.tgnet.TLObject;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes5.dex */
public class TLRPCImToken {

    public static class TL_GetTokensV1 extends TLObject {
        public static int constructor = -945605970;
        public boolean digitalAndordinaryWallet;
        public boolean digitalWallet;
        public ArrayList<String> old_tokens = new ArrayList<>();
        public boolean ordinaryWallet;
        public int refresh;
        private int types;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TL_AllToken.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            int i = this.digitalWallet ? this.types | 1 : this.types & (-2);
            this.types = i;
            int i2 = this.ordinaryWallet ? i | 2 : i & (-3);
            this.types = i2;
            int i3 = this.digitalAndordinaryWallet ? i2 | 4 : i2 & (-5);
            this.types = i3;
            stream.writeInt32(i3);
            stream.writeInt32(this.refresh);
            stream.writeInt32(481674261);
            int count = this.old_tokens.size();
            stream.writeInt32(count);
            for (int i4 = 0; i4 < count; i4++) {
                stream.writeString(this.old_tokens.get(i4));
            }
        }
    }

    public static class TL_AllToken extends TLObject {
        public static int constructor = 610385568;
        public ArrayList<TL_Token> tokens = new ArrayList<>();

        public static TL_AllToken TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (constructor != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in TL_AllToken", Integer.valueOf(constructor2)));
                }
                return null;
            }
            TL_AllToken result = new TL_AllToken();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            int magic = stream.readInt32(exception);
            if (magic != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic)));
                }
                return;
            }
            int count = stream.readInt32(exception);
            for (int a = 0; a < count; a++) {
                TL_Token object = TL_Token.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (object == null) {
                    return;
                }
                this.tokens.add(object);
            }
        }

        public ArrayList<TL_Token> getTokenBeans() {
            return this.tokens;
        }
    }

    public static class TL_Token extends TLObject {
        public static int constructor = 1227249459;
        public int expire;
        public String token;
        public int type;

        public static TL_Token TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (constructor != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in TL_Token", Integer.valueOf(constructor2)));
                }
                return null;
            }
            TL_Token result = new TL_Token();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.type = stream.readInt32(exception);
            this.token = stream.readString(exception);
            this.expire = stream.readInt32(exception);
        }
    }

    @Deprecated
    public static class TL_DigtalReqPqV1 extends TLObject {
        public static int constructor = 2043024112;
        public String nonce;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TL_DigtalRepPqV1.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeString(this.nonce);
        }
    }

    @Deprecated
    public static class TL_DigtalRepPqV1 extends TLObject {
        public static int constructor = -1087383368;
        public boolean digital_wallet;
        public int expire;
        public String server_nonce;
        public String token;

        public static TL_DigtalRepPqV1 TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (constructor != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in TL_Token", Integer.valueOf(constructor2)));
                }
                return null;
            }
            TL_DigtalRepPqV1 result = new TL_DigtalRepPqV1();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.token = stream.readString(exception);
            this.server_nonce = stream.readString(exception);
            this.expire = stream.readInt32(exception);
            this.digital_wallet = stream.readBool(exception);
        }
    }
}
