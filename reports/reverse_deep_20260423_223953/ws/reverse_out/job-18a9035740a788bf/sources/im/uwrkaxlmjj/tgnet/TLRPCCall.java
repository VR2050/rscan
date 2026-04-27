package im.uwrkaxlmjj.tgnet;

import im.uwrkaxlmjj.tgnet.TLRPC;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes2.dex */
public class TLRPCCall {

    public static class TL_UpdateMeetCallEmpty extends TLObject {
        public static int constructor = 1261461260;
        public String id;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Update.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeString(this.id);
        }
    }

    public static class TL_UpdateMeetCall extends TLRPC.Update {
        public static int constructor = -392332264;
        public int admin_id;
        public int date;
        public int flags;
        public String id;
        public boolean isPc;
        public long key_fingerPrint;
        public ArrayList<TLRPC.InputPeer> participant_id = new ArrayList<>();
        public boolean video;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Update.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            int i = this.video ? this.flags | 1 : this.flags & (-2);
            this.flags = i;
            stream.writeInt32(i);
            stream.writeString(this.id);
            stream.writeInt32(this.date);
            stream.writeInt32(this.admin_id);
            stream.writeInt32(481674261);
            int count = this.participant_id.size();
            for (int i2 = 0; i2 < count; i2++) {
                this.participant_id.get(i2).serializeToStream(stream);
            }
            stream.writeInt64(this.key_fingerPrint);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            int int32 = stream.readInt32(exception);
            this.flags = int32;
            this.video = (int32 & 1) != 0;
            this.isPc = (this.flags & 2) != 0;
            this.id = stream.readString(exception);
            this.date = stream.readInt32(exception);
            this.admin_id = stream.readInt32(exception);
            int magic = stream.readInt32(exception);
            if (magic != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic)));
                }
                return;
            }
            int count = stream.readInt32(exception);
            for (int a = 0; a < count; a++) {
                TLRPC.InputPeer inputPeer = TLRPC.InputPeer.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (inputPeer == null) {
                    return;
                }
                this.participant_id.add(inputPeer);
            }
            this.key_fingerPrint = stream.readInt64(exception);
        }
    }

    public static class TL_UpdateMeetCallWaiting extends TLRPC.Update {
        public static int constructor = -1773961835;
        public int admin_id;
        public String appid;
        public TLRPC.TL_dataJSON data;
        public int date;
        public int flags;
        public String id;
        public int receive_date;
        public String token;
        public boolean video;
        public ArrayList<TLRPC.InputPeer> participant_id = new ArrayList<>();
        public ArrayList<String> gslb = new ArrayList<>();

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Updates.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            int i = this.video ? this.flags | 32 : this.flags & (-33);
            this.flags = i;
            stream.writeInt32(i);
            stream.writeString(this.id);
            stream.writeInt32(this.date);
            stream.writeInt32(this.admin_id);
            stream.writeInt32(481674261);
            int count = this.participant_id.size();
            for (int i2 = 0; i2 < count; i2++) {
                this.participant_id.get(i2).serializeToStream(stream);
            }
            int i3 = this.flags;
            if ((i3 & 1) != 0) {
                stream.writeInt32(this.receive_date);
            }
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            int int32 = stream.readInt32(exception);
            this.flags = int32;
            this.video = (int32 & 32) != 0;
            this.id = stream.readString(exception);
            this.date = stream.readInt32(exception);
            this.admin_id = stream.readInt32(exception);
            int magic = stream.readInt32(exception);
            if (magic != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic)));
                }
                return;
            }
            int count = stream.readInt32(exception);
            for (int a = 0; a < count; a++) {
                TLRPC.InputPeer inputPeer = TLRPC.InputPeer.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (inputPeer == null) {
                    return;
                }
                this.participant_id.add(inputPeer);
            }
            int a2 = this.flags;
            if ((a2 & 1) != 0) {
                this.receive_date = stream.readInt32(exception);
            }
            if ((this.flags & 2) != 0) {
                this.token = stream.readString(exception);
            }
            if ((this.flags & 4) != 0) {
                this.appid = stream.readString(exception);
            }
            if ((this.flags & 8) != 0) {
                int imagic = stream.readInt32(exception);
                if (imagic != 481674261) {
                    if (exception) {
                        throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(imagic)));
                    }
                    return;
                }
                int icount = stream.readInt32(exception);
                for (int a3 = 0; a3 < icount; a3++) {
                    String strTmp = stream.readString(exception);
                    if (strTmp == null) {
                        return;
                    }
                    this.gslb.add(strTmp);
                }
            }
            int icount2 = this.flags;
            if ((icount2 & 16) != 0) {
                this.data = TLRPC.TL_dataJSON.TLdeserialize(stream, stream.readInt32(exception), exception);
            }
        }
    }

    public static class TL_UpdateMeetCallRequested extends TLRPC.Update {
        public static int constructor = 241392820;
        public int admin_id;
        public String appid;
        public TLRPC.TL_dataJSON data;
        public int date;
        public int flags;
        public String id;
        public String token;
        public boolean video;
        public ArrayList<TLRPC.InputPeer> participant_id = new ArrayList<>();
        public ArrayList<String> gslb = new ArrayList<>();

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Update.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            int i = this.video ? this.flags | 32 : this.flags & (-33);
            this.flags = i;
            stream.writeInt32(i);
            stream.writeInt32(this.date);
            stream.writeInt32(this.admin_id);
            stream.writeInt32(481674261);
            int count = this.participant_id.size();
            for (int i2 = 0; i2 < count; i2++) {
                this.participant_id.get(i2).serializeToStream(stream);
            }
            stream.writeString(this.token);
            stream.writeString(this.appid);
            stream.writeInt32(481674261);
            int count2 = this.gslb.size();
            for (int i3 = 0; i3 < count2; i3++) {
                stream.writeString(this.gslb.get(i3));
            }
            this.data.serializeToStream(stream);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            int int32 = stream.readInt32(exception);
            this.flags = int32;
            this.video = (int32 & 32) != 0;
            this.id = stream.readString(exception);
            this.date = stream.readInt32(exception);
            this.admin_id = stream.readInt32(exception);
            int magic = stream.readInt32(exception);
            if (magic != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic)));
                }
                return;
            }
            int count = stream.readInt32(exception);
            for (int a = 0; a < count; a++) {
                TLRPC.InputPeer inputPeer = TLRPC.InputPeer.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (inputPeer == null) {
                    return;
                }
                this.participant_id.add(inputPeer);
            }
            this.token = stream.readString(exception);
            this.appid = stream.readString(exception);
            int imagic = stream.readInt32(exception);
            if (imagic != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(imagic)));
                }
                return;
            }
            int icount = stream.readInt32(exception);
            for (int a2 = 0; a2 < icount; a2++) {
                String strTmp = stream.readString(exception);
                if (strTmp == null) {
                    return;
                }
                this.gslb.add(strTmp);
            }
            int a3 = stream.readInt32(exception);
            this.data = TLRPC.TL_dataJSON.TLdeserialize(stream, a3, exception);
        }
    }

    public static class TL_UpdateMeetCallAccepted extends TLRPC.Update {
        public static int constructor = 117720172;
        public int admin_id;
        public int date;
        public int flags;
        public String id;
        public ArrayList<TLRPC.InputPeer> participant_id = new ArrayList<>();
        public boolean video;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Update.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            int i = this.video ? this.flags | 32 : this.flags & (-33);
            this.flags = i;
            stream.writeInt32(i);
            stream.writeString(this.id);
            stream.writeInt32(this.date);
            stream.writeInt32(this.admin_id);
            stream.writeInt32(481674261);
            int count = this.participant_id.size();
            for (int i2 = 0; i2 < count; i2++) {
                this.participant_id.get(i2).serializeToStream(stream);
            }
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            int int32 = stream.readInt32(exception);
            this.flags = int32;
            this.video = (int32 & 32) != 0;
            this.id = stream.readString(exception);
            this.date = stream.readInt32(exception);
            this.admin_id = stream.readInt32(exception);
            int magic = stream.readInt32(exception);
            if (magic != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic)));
                }
                return;
            }
            int count = stream.readInt32(exception);
            for (int a = 0; a < count; a++) {
                TLRPC.InputPeer inputPeer = TLRPC.InputPeer.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (inputPeer == null) {
                    return;
                }
                this.participant_id.add(inputPeer);
            }
        }
    }

    public static class TL_UpdateMeetCallDiscarded extends TLRPC.Update {
        public static int constructor = 1975844770;
        public int duration;
        public int flags;
        public String id;
        public boolean video;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Update.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            int i = this.video ? this.flags | 32 : this.flags & (-33);
            this.flags = i;
            stream.writeInt32(i);
            stream.writeString(this.id);
            if ((this.flags & 2) != 0) {
                stream.writeInt32(this.duration);
            }
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            int int32 = stream.readInt32(exception);
            this.flags = int32;
            this.video = (int32 & 32) != 0;
            this.id = stream.readString(exception);
            if ((this.flags & 2) != 0) {
                this.duration = stream.readInt32(exception);
            }
        }
    }

    public static class TL_UpdateMeetCallHistory extends TLRPC.TL_updates {
        public static int constructor = -1140700830;
        public TLRPC.TL_dataJSON data;
        public int flags;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLRPC.Update deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Update.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            this.data.serializeToStream(stream);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLRPC.TL_updates, im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.data = TLRPC.TL_dataJSON.TLdeserialize(stream, stream.readInt32(exception), exception);
        }
    }

    public static class TL_InputMeetCall extends TLObject {
        public static int constructor = -1472010869;
        public String id;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TL_InputMeetCall deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (constructor != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in InputmeetCall", Integer.valueOf(constructor2)));
                }
                return null;
            }
            TL_InputMeetCall result = new TL_InputMeetCall();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeString(this.id);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.id = stream.readString(exception);
        }
    }

    public static class TL_VideoConfig extends TLObject {
        public static int constructor = 1430593449;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLRPC.TL_dataJSON deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.TL_dataJSON.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
        }
    }

    public static class TL_MeetRequestCall extends TLObject {
        public static int constructor = 761572648;
        public TLRPC.InputPeer channel_id;
        public int flags;
        public long random_id;
        public ArrayList<TLRPC.InputPeer> userIdList = new ArrayList<>();
        public boolean video;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Updates.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            int i = this.video ? this.flags | 1 : this.flags & (-2);
            this.flags = i;
            stream.writeInt32(i);
            if ((this.flags & 2) != 0) {
                stream.writeInt32(481674261);
                int count = this.userIdList.size();
                stream.writeInt32(count);
                for (int i2 = 0; i2 < count; i2++) {
                    this.userIdList.get(i2).serializeToStream(stream);
                }
            }
            if ((this.flags & 4) != 0) {
                this.channel_id.serializeToStream(stream);
            }
            stream.writeInt64(this.random_id);
        }
    }

    public static class TL_MeetAcceptCall extends TLObject {
        public static int constructor = -1711386009;
        public TL_InputMeetCall peer;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLRPC.Updates deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Updates.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            this.peer.serializeToStream(stream);
        }
    }

    public static class TL_MeetConfirmCall extends TLObject {
        public static int constructor = 2037433910;
        public long key_fingerprint;
        public TL_InputMeetCall peer;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLRPC.Updates deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Updates.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            this.peer.serializeToStream(stream);
            stream.writeInt64(this.key_fingerprint);
        }
    }

    public static class TL_MeetKeepCallV1 extends TLObject {
        public static int constructor = 172728919;
        public TL_InputMeetCall peer;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Updates.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            this.peer.serializeToStream(stream);
        }
    }

    public static class TL_MeetModel extends TLRPC.Updates {
        public static int constructor = -534468978;
        public int flags;
        public String id;
        public boolean video;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            int i = this.video ? this.flags | 1 : this.flags & (-2);
            this.flags = i;
            stream.writeInt32(i);
            stream.writeString(this.id);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.flags = stream.readInt32(exception);
            this.id = stream.readString(exception);
            this.video = (this.flags & 1) != 0;
        }
    }

    public static class TL_MeetReceivedCall extends TLObject {
        public static int constructor = -2143433199;
        public TL_InputMeetCall peer;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLRPC.Bool deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Bool.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            this.peer.serializeToStream(stream);
        }
    }

    public static class TL_MeetDiscardCall extends TLObject {
        public static int constructor = -934946139;
        public int duration;
        public int flags;
        public TL_InputMeetCall peer;
        public TLRPC.PhoneCallDiscardReason reason;
        public boolean video;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLRPC.Updates deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Updates.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            int i = this.video ? this.flags | 1 : this.flags & (-2);
            this.flags = i;
            stream.writeInt32(i);
            this.peer.serializeToStream(stream);
            stream.writeInt32(this.duration);
            this.reason.serializeToStream(stream);
        }
    }

    public static class TL_MeetGetCallHistory extends TLObject {
        public static int constructor = -521451147;
        public int add_offset;
        public int flags;
        public int hash;
        public int limit;
        public int max_id;
        public int min_id;
        public int offset_date;
        public int offset_id;
        public TLRPC.InputPeer peer;
        public boolean video;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLRPC.Updates deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Updates.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            int i = this.video ? this.flags | 32 : this.flags & (-33);
            this.flags = i;
            stream.writeInt32(i);
            this.peer.serializeToStream(stream);
            stream.writeInt32(this.offset_id);
            stream.writeInt32(this.offset_date);
            stream.writeInt32(this.add_offset);
            stream.writeInt32(this.limit);
            stream.writeInt32(this.max_id);
            stream.writeInt32(this.min_id);
            stream.writeInt32(this.hash);
        }
    }

    public static class TL_hub_getOtherConfig extends TLObject {
        public static int constructor = 307107699;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TL_OtherConfig deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TL_OtherConfig.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
        }
    }

    public static class TL_OtherConfig extends TLObject {
        public static int constructor = 1929982835;
        public ArrayList addrs = new ArrayList();
        public TLRPC.TL_dataJSON data;

        public static TL_OtherConfig TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (constructor != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in TL_OtherConfig", Integer.valueOf(constructor2)));
                }
                return null;
            }
            TL_OtherConfig result = new TL_OtherConfig();
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
                String addr = stream.readString(exception);
                this.addrs.add(addr);
            }
            int a2 = stream.readInt32(exception);
            this.data = TLRPC.TL_dataJSON.TLdeserialize(stream, a2, exception);
        }
    }

    public static class TL_MeetChangeCall extends TLObject {
        public static int constructor = 1239003785;
        public int flags;
        public TL_InputMeetCall peer;
        public boolean video;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Update.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            int i = this.video ? this.flags | 1 : this.flags & (-2);
            this.flags = i;
            stream.writeInt32(i);
            this.peer.serializeToStream(stream);
        }
    }

    public static class TL_UpdateMeetChangeCall extends TLRPC.Update {
        public static int constructor = -268456246;
        public int flags;
        public String id;
        public boolean video;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Update.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            int i = this.video ? this.flags | 1 : this.flags & (-2);
            this.flags = i;
            stream.writeInt32(i);
            stream.writeString(this.id);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            int int32 = stream.readInt32(exception);
            this.flags = int32;
            this.video = (int32 & 1) != 0;
            this.id = stream.readString(exception);
        }
    }
}
