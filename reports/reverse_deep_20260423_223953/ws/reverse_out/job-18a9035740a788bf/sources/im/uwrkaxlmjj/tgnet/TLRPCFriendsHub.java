package im.uwrkaxlmjj.tgnet;

import im.uwrkaxlmjj.tgnet.TLRPC;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes2.dex */
public class TLRPCFriendsHub {

    public static class TL_GetOtherConfig extends TLObject {
        public static int constructor = 2017161851;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TL_OtherConfig.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
        }
    }

    public static class TL_OtherConfig extends TLObject {
        public static int constructor = 1929982835;
        public ArrayList<String> addrs = new ArrayList<>();
        public TLRPC.TL_dataJSON data;

        public static TL_OtherConfig TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (constructor != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("------->can't parse magic %x in TL_PaymentOrderList", Integer.valueOf(constructor2)));
                }
                return null;
            }
            TL_OtherConfig order = new TL_OtherConfig();
            order.readParams(stream, exception);
            return order;
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
            int size = stream.readInt32(exception);
            for (int i = 0; i < size; i++) {
                String addr = stream.readString(exception);
                this.addrs.add(addr);
            }
            int i2 = stream.readInt32(exception);
            this.data = TLRPC.TL_dataJSON.TLdeserialize(stream, i2, exception);
        }
    }
}
