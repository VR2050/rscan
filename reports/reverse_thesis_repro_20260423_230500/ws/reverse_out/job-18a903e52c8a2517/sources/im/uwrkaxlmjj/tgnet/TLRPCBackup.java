package im.uwrkaxlmjj.tgnet;

import java.util.ArrayList;

/* JADX INFO: loaded from: classes2.dex */
public class TLRPCBackup {

    public static class CL_java_simpleConfig extends TLObject {
        public static final int constructor = 1515793004;
        public int date;
        public int expires;
        public ArrayList<CL_java_ipPortRule> rules = new ArrayList<>();

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.date);
            stream.writeInt32(this.expires);
            int count = this.rules.size();
            stream.writeInt32(count);
            for (CL_java_ipPortRule rule : this.rules) {
                rule.serializeToStream(stream);
            }
        }
    }

    public static final class CL_java_ipPortRule extends TLObject {
        public static final int constructor = 1182381663;
        public int dc_id;
        public ArrayList<CL_java_ipPort> ips = new ArrayList<>();
        public String phone_prefix_rules;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeString(this.phone_prefix_rules);
            stream.writeInt32(this.dc_id);
            int count = this.ips.size();
            stream.writeInt32(count);
            for (CL_java_ipPort ip : this.ips) {
                ip.serializeToStream(stream);
            }
        }
    }

    public static final class CL_java_ipPort extends TLObject {
        public static final int constructor = -734810765;
        public int ipv4;
        public int port;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.ipv4);
            stream.writeInt32(this.port);
        }
    }
}
