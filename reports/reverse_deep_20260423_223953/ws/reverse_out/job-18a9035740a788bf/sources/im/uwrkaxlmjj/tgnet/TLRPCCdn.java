package im.uwrkaxlmjj.tgnet;

import im.uwrkaxlmjj.tgnet.TLRPC;

/* JADX INFO: loaded from: classes2.dex */
public class TLRPCCdn {

    public static class TL_setCdnVipAutoPay extends TLObject {
        public static final int constructor = 2103578704;
        public boolean is_open;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TL_userCdnVipInfo.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeBool(this.is_open);
        }
    }

    public static class TL_getUserCdnVipInfo extends TLObject {
        public static final int constructor = -1618641118;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TL_userCdnVipInfo.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
        }
    }

    public static class TL_getUserCdnVipPayRecords extends TLObject {
        public static final int constructor = 509839501;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TL_userCdnPayList.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
        }
    }

    public static class TL_payCdnVip extends TLObject {
        public static final int constructor = -902316067;
        public TLRPC.TL_dataJSON req_info;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TL_userCdnVipInfo.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            TLRPC.TL_dataJSON tL_dataJSON = this.req_info;
            if (tL_dataJSON != null) {
                tL_dataJSON.serializeToStream(stream);
            }
        }
    }

    public static class TL_payCdnResult extends TLObject {
        public static final int constructor = 761144686;
        public TLRPC.TL_dataJSON pay_res;
        public TL_userCdnVipInfo vip_info;

        public static TLObject TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (761144686 != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in TLRPCCdn_TL_payCdnResult", Integer.valueOf(constructor2)));
                }
                return null;
            }
            TL_payCdnResult result = new TL_payCdnResult();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.pay_res = TLRPC.TL_dataJSON.TLdeserialize(stream, stream.readInt32(exception), exception);
            this.vip_info = TL_userCdnVipInfo.TLdeserialize(stream, stream.readInt32(exception), exception);
        }
    }

    public static class TL_userCdnVipInfo extends TLObject {
        public static final int constructor = -235131565;
        public TLRPC.TL_dataJSON vip_info;

        public static TL_userCdnVipInfo TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (-235131565 != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in TLRPCCdn_TL_userCdnVipInfo", Integer.valueOf(constructor2)));
                }
                return null;
            }
            TL_userCdnVipInfo result = new TL_userCdnVipInfo();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.vip_info = TLRPC.TL_dataJSON.TLdeserialize(stream, stream.readInt32(exception), exception);
        }
    }

    public static class TL_userCdnPayList extends TLObject {
        public static final int constructor = 502299450;
        public TLRPC.TL_dataJSON pay_list;

        public static TL_userCdnPayList TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (502299450 != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in TLRPCCdn_TL_userCdnPayList", Integer.valueOf(constructor2)));
                }
                return null;
            }
            TL_userCdnPayList result = new TL_userCdnPayList();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.pay_list = TLRPC.TL_dataJSON.TLdeserialize(stream, stream.readInt32(exception), exception);
        }
    }
}
