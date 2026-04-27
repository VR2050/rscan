package im.uwrkaxlmjj.tgnet;

import com.blankj.utilcode.util.GsonUtils;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public class TLRPCContacts {

    public static class ContactsRequestApply extends TLObject {
        public static int constructor = -1724300775;
        public String first_name;
        public int flag;
        public int from_type;
        public String greet;
        public int group_id;
        public TLRPC.InputUser inputUser;
        public String last_name;
        public String phone;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Updates.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.flag);
            if ((this.flag & 1) != 0) {
                stream.writeString(this.phone);
            }
            stream.writeInt32(this.from_type);
            this.inputUser.serializeToStream(stream);
            stream.writeString(this.first_name);
            stream.writeString(this.last_name);
            stream.writeString(this.greet);
            stream.writeInt32(this.group_id);
        }
    }

    public static class GreetApply extends TLObject {
        public static int constructor = 402249381;
        public int apply_id;
        public String greet;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Update.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.apply_id);
            stream.writeString(this.greet);
        }
    }

    public static class UpdateNewGreet extends TLRPC.Update {
        public static int constructor = 1887998186;
        public ContactApplyInfo apply_info;
        public int unread_count;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.apply_info = ContactApplyInfo.TLdeserialize(stream, stream.readInt32(exception), exception);
            this.unread_count = stream.readInt32(exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            this.apply_info.serializeToStream(stream);
            stream.writeInt32(this.unread_count);
        }
    }

    public static class GetContactApplyGreeting extends TLObject {
        public static int constructor = 10626236;
        public int apply_id;

        public static ApplyGreetDetail TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            return ApplyGreetDetail.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.apply_id);
        }
    }

    public static class AcceptContactApply extends TLObject {
        public static int constructor = 1149618457;
        public int apply_id;
        public String first_name;
        public int group_id;
        public String last_name;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Updates.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.apply_id);
            stream.writeInt32(this.group_id);
            stream.writeString(this.first_name);
            stream.writeString(this.last_name);
        }
    }

    public static class ClearUnreadApply extends TLObject {
        public static int constructor = -1319473854;
        public int max_apply_id;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Bool.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.max_apply_id);
        }
    }

    public static class SearchUserByPhone extends TLObject {
        public static int constructor = -123441452;
        public String phone;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.TL_contacts_found.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeString(this.phone);
        }
    }

    public static class DeleteContactApply extends TLObject {
        public static int constructor = -775715280;
        public DeleteAction action;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Bool.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            this.action.serializeToStream(stream);
        }
    }

    public static class GetContactApplyDifference extends TLObject {
        public static int constructor = -1406184044;
        public int apply_id;
        public int date;
        public int total_limit;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return ContactsApplyDifference.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.apply_id);
            stream.writeInt32(this.total_limit);
            stream.writeInt32(this.date);
        }
    }

    public static class ContactApplyResp extends TLRPC.Update {
        public static int constructor = 1099640995;
        public ContactApplyInfo applyInfo;

        public static ContactApplyResp TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (constructor != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in ContactApplyResp", Integer.valueOf(constructor2)));
                }
                return null;
            }
            ContactApplyResp result = new ContactApplyResp();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            this.applyInfo.serializeToStream(stream);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.applyInfo = ContactApplyInfo.TLdeserialize(stream, stream.readInt32(exception), exception);
        }
    }

    public static class UpdateContactApplyRequested extends TLRPC.Update {
        public static int constructor = 878085410;
        public ContactApplyInfo apply_info;
        public int date;
        public int unread_count;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.apply_info = ContactApplyInfo.TLdeserialize(stream, stream.readInt32(exception), exception);
            this.date = stream.readInt32(exception);
            this.unread_count = stream.readInt32(exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            this.apply_info.serializeToStream(stream);
            stream.writeInt32(this.date);
            stream.writeInt32(this.unread_count);
        }
    }

    public static class ContactApplyInfo extends TLObject {
        public static int constructor = -1150362864;
        public int date;
        public int expire;
        public int for_apply_id;
        public TLRPC.Peer from_peer;
        public String greet;
        public int id;
        public int state;

        public static ContactApplyInfo TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (constructor != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in TL_contacts_link", Integer.valueOf(constructor2)));
                }
                return null;
            }
            ContactApplyInfo result = new ContactApplyInfo();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            super.serializeToStream(stream);
            stream.writeInt32(constructor);
            stream.writeInt32(this.for_apply_id);
            this.from_peer.serializeToStream(stream);
            stream.writeInt32(this.id);
            stream.writeString(this.greet);
            stream.writeInt32(this.state);
            stream.writeInt32(this.date);
            stream.writeInt32(this.expire);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            super.readParams(stream, exception);
            this.for_apply_id = stream.readInt32(exception);
            this.from_peer = TLRPC.Peer.TLdeserialize(stream, stream.readInt32(exception), exception);
            this.id = stream.readInt32(exception);
            this.greet = stream.readString(exception);
            this.state = stream.readInt32(exception);
            this.date = stream.readInt32(exception);
            this.expire = stream.readInt32(exception);
        }
    }

    public static class GreetInfo extends TLObject {
        public static int constructor = -69356502;
        public int data;
        public TLRPC.Peer from_peer;
        public String message;

        public static GreetInfo TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (constructor != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in GreetInfo", Integer.valueOf(constructor2)));
                }
                return null;
            }
            GreetInfo result = new GreetInfo();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            this.from_peer.serializeToStream(stream);
            stream.writeString(this.message);
            stream.writeInt32(this.data);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.from_peer = TLRPC.Peer.TLdeserialize(stream, stream.readInt32(exception), exception);
            this.message = stream.readString(exception);
            this.data = stream.readInt32(exception);
        }
    }

    public static class ApplyGreetDetail extends TLObject {
        public static int constructor = -408532579;
        public ArrayList<GreetInfo> greets = new ArrayList<>();

        public static ApplyGreetDetail TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (constructor != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in ApplyGreetDetail", Integer.valueOf(constructor2)));
                }
                return null;
            }
            ApplyGreetDetail result = new ApplyGreetDetail();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(481674261);
            int count = this.greets.size();
            for (int i = 0; i < count; i++) {
                this.greets.get(i).serializeToStream(stream);
            }
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
                GreetInfo greetInfo = GreetInfo.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (greetInfo == null) {
                    return;
                }
                this.greets.add(greetInfo);
            }
        }
    }

    public static class ContactsApplyDifference extends TLObject {
        public int date;
        public StateConactsApply state;
        public ArrayList<TLRPC.User> users = new ArrayList<>();
        public ArrayList<TLRPC.Update> otherUpdates = new ArrayList<>();

        public static ContactsApplyDifference TLdeserialize(AbstractSerializedData stream, int constructor, boolean exception) {
            ContactsApplyDifference result = null;
            if (constructor == -2037787963) {
                result = new HC_contacts_apply_differenceSlice();
            } else if (constructor == 975517135) {
                result = new HC_contacts_apply_difference();
            } else if (constructor == 1272038938) {
                result = new HC_contacts_apply_differenceEmpty();
            }
            if (result == null && exception) {
                throw new RuntimeException(String.format("can't parse magic %x in ContactsApplyDifference", Integer.valueOf(constructor)));
            }
            if (result != null) {
                result.readParams(stream, exception);
            }
            return result;
        }
    }

    public static class HC_contacts_apply_differenceEmpty extends ContactsApplyDifference {
        public static int constructor = 1272038938;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.date = stream.readInt32(exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.date);
        }
    }

    public static class HC_contacts_apply_difference extends ContactsApplyDifference {
        public static int constructor = 975517135;

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
                TLRPC.User user = TLRPC.User.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (user == null) {
                    return;
                }
                this.users.add(user);
            }
            int magic2 = stream.readInt32(exception);
            if (magic2 != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic2)));
                }
                return;
            }
            int count2 = stream.readInt32(exception);
            for (int a2 = 0; a2 < count2; a2++) {
                TLRPC.Update update = TLRPC.Update.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (update == null) {
                    return;
                }
                this.otherUpdates.add(update);
            }
            int a3 = stream.readInt32(exception);
            this.state = StateConactsApply.TLdeserialize(stream, a3, exception);
        }
    }

    public static class HC_contacts_apply_differenceSlice extends ContactsApplyDifference {
        public static int constructor = -2037787963;

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
                TLRPC.User user = TLRPC.User.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (user == null) {
                    return;
                }
                this.users.add(user);
            }
            int magic2 = stream.readInt32(exception);
            if (magic2 != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic2)));
                }
                return;
            }
            int count2 = stream.readInt32(exception);
            for (int a2 = 0; a2 < count2; a2++) {
                TLRPC.Update update = TLRPC.Update.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (update == null) {
                    return;
                }
                this.otherUpdates.add(update);
            }
            int a3 = stream.readInt32(exception);
            this.state = StateConactsApply.TLdeserialize(stream, a3, exception);
        }
    }

    public static class StateConactsApply extends TLObject {
        public static final int constructor = 393631888;
        public int apply_id;
        public int date;
        public int unread_count;

        public static StateConactsApply TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (393631888 != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in StateConactsApply", Integer.valueOf(constructor2)));
                }
                return null;
            }
            StateConactsApply result = new StateConactsApply();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.apply_id = stream.readInt32(exception);
            this.date = stream.readInt32(exception);
            this.unread_count = stream.readInt32(exception);
        }
    }

    public static class DeleteAction extends TLObject {
        public static DeleteAction TLdeserialize(AbstractSerializedData stream, int constructor, boolean exception) {
            DeleteAction result = null;
            if (constructor == -1398708869) {
                result = new DeleteActionClearHistory();
            } else if (constructor == 1279515160) {
                result = new DeleteActionClearSome();
            }
            if (result == null && exception) {
                throw new RuntimeException(String.format("can't parse magic %x in DeleteAction", Integer.valueOf(constructor)));
            }
            if (result != null) {
                result.readParams(stream, exception);
            }
            return result;
        }
    }

    public static class DeleteActionClearHistory extends DeleteAction {
        public static int constructor = -2048188504;
        public int max_id;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.max_id);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.max_id = stream.readInt32(exception);
        }
    }

    public static class DeleteActionClearSome extends DeleteAction {
        public static int constructor = -1913420369;
        public ArrayList<Integer> ids = new ArrayList<>();

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(481674261);
            int count = this.ids.size();
            stream.writeInt32(count);
            for (int i = 0; i < count; i++) {
                stream.writeInt32(this.ids.get(i).intValue());
            }
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
                Integer id = Integer.valueOf(stream.readInt32(exception));
                if (id == null && id.intValue() == 0) {
                    return;
                }
                this.ids.add(id);
            }
        }
    }

    public static class AccessContactApplyMessageAction extends TLRPC.MessageAction {
        public static int constructor = -1913420369;
        public String message;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.message = stream.readString(exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeString(this.message);
        }
    }

    public static class CL_user_getFulluser extends TLObject {
        public static int constructor = -111001148;
        public TLRPC.InputUser inputUser;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.UserFull.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            this.inputUser.serializeToStream(stream);
        }
    }

    public static class CL_user_updateUserFull extends TLRPC.Update {
        public static int constructor = -769389941;
        public String address;
        public int age;
        public TLRPC.TL_dataJSON extend;
        public int flags;
        public int sex;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Update.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            if ((this.flags & 1) != 0) {
                stream.writeInt32(this.sex);
            }
            if ((this.flags & 2) != 0) {
                stream.writeInt32(this.age);
            }
            if ((this.flags & 4) != 0) {
                stream.writeString(this.address);
            }
            if ((this.flags & 8) != 0) {
                this.extend.serializeToStream(stream);
            }
        }
    }

    public static class CL_userFull_v1 extends TLRPC.UserFull {
        public static int constructor = 1967396760;
        public TLRPC.TL_dataJSON extend;
        private CL_userFull_v1_Bean extendBean;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            this.flags = this.blocked ? this.flags | 1 : this.flags & (-2);
            this.flags = this.phone_calls_available ? this.flags | 16 : this.flags & (-17);
            this.flags = this.phone_calls_private ? this.flags | 32 : this.flags & (-33);
            this.flags = this.can_pin_message ? this.flags | 128 : this.flags & (-129);
            this.flags = this.has_scheduled ? this.flags | 4096 : this.flags & (-4097);
            stream.writeInt32(this.flags);
            this.user.serializeToStream(stream);
            if ((this.flags & 2) != 0) {
                stream.writeString(this.about);
            }
            this.settings.serializeToStream(stream);
            if ((this.flags & 4) != 0) {
                this.profile_photo.serializeToStream(stream);
            }
            this.notify_settings.serializeToStream(stream);
            if ((this.flags & 8) != 0) {
                this.bot_info.serializeToStream(stream);
            }
            if ((this.flags & 64) != 0) {
                stream.writeInt32(this.pinned_msg_id);
            }
            stream.writeInt32(this.common_chats_count);
            if ((this.flags & 2048) != 0) {
                stream.writeInt32(this.folder_id);
            }
            this.extend.serializeToStream(stream);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.flags = stream.readInt32(exception);
            this.blocked = (this.flags & 1) != 0;
            this.phone_calls_available = (this.flags & 16) != 0;
            this.phone_calls_private = (this.flags & 32) != 0;
            this.can_pin_message = (this.flags & 128) != 0;
            this.has_scheduled = (this.flags & 4096) != 0;
            this.user = TLRPC.User.TLdeserialize(stream, stream.readInt32(exception), exception);
            if ((this.flags & 2) != 0) {
                this.about = stream.readString(exception);
            }
            this.settings = TLRPC.TL_peerSettings.TLdeserialize(stream, stream.readInt32(exception), exception);
            if ((this.flags & 4) != 0) {
                this.profile_photo = TLRPC.Photo.TLdeserialize(stream, stream.readInt32(exception), exception);
            }
            this.notify_settings = TLRPC.PeerNotifySettings.TLdeserialize(stream, stream.readInt32(exception), exception);
            if ((this.flags & 8) != 0) {
                this.bot_info = TLRPC.BotInfo.TLdeserialize(stream, stream.readInt32(exception), exception);
            }
            if ((this.flags & 64) != 0) {
                this.pinned_msg_id = stream.readInt32(exception);
            }
            this.common_chats_count = stream.readInt32(exception);
            if ((this.flags & 2048) != 0) {
                this.folder_id = stream.readInt32(exception);
            }
            this.extend = TLRPC.TL_dataJSON.TLdeserialize(stream, stream.readInt32(exception), exception);
        }

        public CL_userFull_v1_Bean getExtendBean() {
            TLRPC.TL_dataJSON tL_dataJSON = this.extend;
            if (tL_dataJSON != null && tL_dataJSON.data != null && this.extendBean == null) {
                this.extendBean = (CL_userFull_v1_Bean) GsonUtils.fromJson(this.extend.data, CL_userFull_v1_Bean.class);
            }
            return this.extendBean;
        }
    }

    public static class CL_userFull_v1_Bean {
        public String address;
        public int age;
        public int birthday;
        public int group_id;
        public String group_name;
        public boolean moment;
        public int sex;
        public int source;
        public UserAlbumsBean userAlbumsReq;
        public int user_type;
        public boolean vip;
        private int vipexpire;
        public int viplevel;

        public static class Albums {
            public int Ext;
            public String Name;
            public String Thum;
        }

        public static class UserAlbumsBean {
            public ArrayList<Albums> albums;
            public int code;
            public String msg;
        }

        public boolean needCompletedUserInfor() {
            return false;
        }

        public boolean cdnVipIsAvailable() {
            int i;
            return this.vip && (i = this.vipexpire) != 0 && i >= ConnectionsManager.getInstance(UserConfig.selectedAccount).getCurrentTime();
        }
    }

    public static class UpdateResetContactsApplyUnread extends TLRPC.Update {
        public static int constructor = -1787295028;
        public int max_id;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.max_id = stream.readInt32(exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.max_id);
        }
    }

    public static class UpdateRegetContactsApplies extends TLRPC.Update {
        public static int constructor = -185154261;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
        }
    }

    public static class FromType extends TLObject {
        public static int constructor = -248217099;
        public int from_type;
        public int user_id;

        public static FromType TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (constructor != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse constructor %x in FromType", Integer.valueOf(constructor2)));
                }
                return null;
            }
            FromType result = new FromType();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.user_id);
            stream.writeInt32(this.from_type);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.user_id = stream.readInt32(exception);
            this.from_type = stream.readInt32(exception);
        }
    }

    public static class GetContactAppliesDifferenceV2 extends TLObject {
        public static int constructor = 1842013182;
        public int apply_id;
        public int date;
        public long hash;
        public int total_limit;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return ContactsAppiesDifferenceV2.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.apply_id);
            stream.writeInt32(this.total_limit);
            stream.writeInt32(this.date);
            stream.writeInt64(this.hash);
        }
    }

    public static class ContactsAppiesDifferenceV2 extends TLObject {
        public long hash;
        public StateConactsApply state;
        public ArrayList<TLRPC.User> users = new ArrayList<>();
        public ArrayList<TLRPC.Update> otherUpdates = new ArrayList<>();
        public ArrayList<FromType> peerTypes = new ArrayList<>();

        public static ContactsAppiesDifferenceV2 TLdeserialize(AbstractSerializedData stream, int constructor, boolean exception) {
            ContactsAppiesDifferenceV2 result = null;
            if (constructor == -1321218444) {
                result = new HC_contacts_apply_differenceSlice_v2();
            } else if (constructor == -368745101) {
                result = new HC_contacts_apply_notModified();
            } else if (constructor == 994632856) {
                result = new HC_contacts_apply_difference_v2();
            }
            if (result == null && exception) {
                throw new RuntimeException(String.format("can't parse magic %x in ContactsApplyDifference", Integer.valueOf(constructor)));
            }
            if (result != null) {
                result.readParams(stream, exception);
            }
            return result;
        }
    }

    public static class HC_contacts_apply_difference_v2 extends ContactsAppiesDifferenceV2 {
        public static int constructor = 994632856;

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
                FromType fromType = FromType.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (fromType == null) {
                    return;
                }
                this.peerTypes.add(fromType);
            }
            int magic2 = stream.readInt32(exception);
            if (magic2 != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic2)));
                }
                return;
            }
            int count2 = stream.readInt32(exception);
            for (int a2 = 0; a2 < count2; a2++) {
                TLRPC.User user = TLRPC.User.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (user == null) {
                    return;
                }
                this.users.add(user);
            }
            int magic3 = stream.readInt32(exception);
            if (magic3 != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic3)));
                }
                return;
            }
            int count3 = stream.readInt32(exception);
            for (int a3 = 0; a3 < count3; a3++) {
                TLRPC.Update update = TLRPC.Update.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (update == null) {
                    return;
                }
                this.otherUpdates.add(update);
            }
            int a4 = stream.readInt32(exception);
            this.state = StateConactsApply.TLdeserialize(stream, a4, exception);
            this.hash = stream.readInt64(exception);
        }
    }

    public static class HC_contacts_apply_differenceSlice_v2 extends ContactsAppiesDifferenceV2 {
        public static int constructor = -1321218444;

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
                TLRPC.User user = TLRPC.User.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (user == null) {
                    return;
                }
                this.users.add(user);
            }
            int magic2 = stream.readInt32(exception);
            if (magic2 != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic2)));
                }
                return;
            }
            int count2 = stream.readInt32(exception);
            for (int a2 = 0; a2 < count2; a2++) {
                TLRPC.Update update = TLRPC.Update.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (update == null) {
                    return;
                }
                this.otherUpdates.add(update);
            }
            int a3 = stream.readInt32(exception);
            this.state = StateConactsApply.TLdeserialize(stream, a3, exception);
        }
    }

    public static class HC_contacts_apply_notModified extends ContactsAppiesDifferenceV2 {
        public static int constructor = -368745101;
        public int date;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.date = stream.readInt32(exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.date);
        }
    }

    public static class TL_getCustomerLables extends TLObject {
        public static int constructor = -416451414;
        public long hash;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TL_CustomerLables deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TL_CustomerLables.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt64(this.hash);
        }
    }

    public static class TL_CustomerLable extends TLObject {
        public static int constructor = 2133787810;
        public TLRPC.PhotoSize lableInfo;
        public int userType;

        public static TL_CustomerLable TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (constructor != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in TL_CustomerLable", Integer.valueOf(constructor2)));
                }
                return null;
            }
            TL_CustomerLable result = new TL_CustomerLable();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.userType = stream.readInt32(exception);
            this.lableInfo = TLRPC.PhotoSize.TLdeserialize(stream, stream.readInt32(exception), exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.userType);
            this.lableInfo.serializeToStream(stream);
        }
    }

    public static class TL_CustomerLables extends TLObject {
        public static TL_CustomerLables TLdeserialize(AbstractSerializedData stream, int constructor, boolean exception) {
            TL_CustomerLables result = null;
            if (constructor == -1570157459) {
                result = new TL_customerLablesModified();
            } else if (constructor == -983639668) {
                result = new TL_customerLablesNotModified();
            }
            if (result == null && exception) {
                throw new RuntimeException(String.format("can't parse magic %x in TL_CustomerLables", Integer.valueOf(constructor)));
            }
            if (result != null) {
                result.readParams(stream, exception);
            }
            return result;
        }
    }

    public static class TL_customerLablesNotModified extends TL_CustomerLables {
        public static int constructor = -983639668;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            super.readParams(stream, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
        }
    }

    public static class TL_customerLablesModified extends TL_CustomerLables {
        public static int constructor = -1570157459;
        public long hash;
        public ArrayList<TL_CustomerLable> lables = new ArrayList<>();

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            super.readParams(stream, exception);
            this.hash = stream.readInt64(exception);
            int magic = stream.readInt32(exception);
            if (magic != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic)));
                }
                return;
            }
            int size = stream.readInt32(exception);
            for (int i = 0; i < size; i++) {
                TL_CustomerLable lable = TL_CustomerLable.TLdeserialize(stream, stream.readInt32(exception), exception);
                this.lables.add(lable);
            }
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt64(this.hash);
            stream.writeInt32(this.lables.size());
            for (TL_CustomerLable lable : this.lables) {
                lable.serializeToStream(stream);
            }
        }
    }

    public static class TL_getContactsV1 extends TLObject {
        public static int constructor = 1443777194;
        public int hash;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.contacts_Contacts.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.hash);
        }
    }

    public static class TL_contactV1 extends TLRPC.Contact {
        public static int constructor = -544923135;
        public String about;
        public int group_id;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.user_id = stream.readInt32(exception);
            this.mutual = stream.readBool(exception);
            this.group_id = stream.readInt32(exception);
            this.about = stream.readString(exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.user_id);
            stream.writeBool(this.mutual);
            stream.writeInt32(this.group_id);
            stream.writeString(this.about);
        }
    }

    public static class TL_contactsV1 extends TLRPC.contacts_Contacts {
        public static int constructor = -220975312;
        public List<TL_contactsGroupInfo> group_infos = new ArrayList();
        public int hash;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.hash = stream.readInt32(exception);
            int magic = stream.readInt32(exception);
            if (magic != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic)));
                }
                return;
            }
            int count = stream.readInt32(exception);
            for (int i = 0; i < count; i++) {
                this.contacts.add(TLRPC.Contact.TLdeserialize(stream, stream.readInt32(exception), exception));
            }
            int i2 = stream.readInt32(exception);
            this.saved_count = i2;
            int magic2 = stream.readInt32(exception);
            if (magic2 != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic2)));
                }
                return;
            }
            int count2 = stream.readInt32(exception);
            for (int i3 = 0; i3 < count2; i3++) {
                this.users.add(TLRPC.User.TLdeserialize(stream, stream.readInt32(exception), exception));
            }
            int magic3 = stream.readInt32(exception);
            if (magic3 != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic3)));
                }
                return;
            }
            int count3 = stream.readInt32(exception);
            for (int i4 = 0; i4 < count3; i4++) {
                this.group_infos.add(TL_contactsGroupInfo.TLdeserialize(stream, stream.readInt32(exception), exception));
            }
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.hash);
            stream.writeInt32(481674261);
            int count = this.contacts.size();
            stream.writeInt32(count);
            for (int a = 0; a < count; a++) {
                this.contacts.get(a).serializeToStream(stream);
            }
            int a2 = this.saved_count;
            stream.writeInt32(a2);
            stream.writeInt32(481674261);
            int count2 = this.users.size();
            stream.writeInt32(count2);
            for (int a3 = 0; a3 < count2; a3++) {
                this.users.get(a3).serializeToStream(stream);
            }
            stream.writeInt32(481674261);
            int count3 = this.group_infos.size();
            stream.writeInt32(count3);
            for (int a4 = 0; a4 < count3; a4++) {
                this.group_infos.get(a4).serializeToStream(stream);
            }
        }
    }

    public static class TL_contactsGroupInfo extends TLObject {
        public static int constructor = 351052466;
        public int date;
        public int group_id;
        public int order_id;
        public String title;

        public static TL_contactsGroupInfo TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (constructor != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in TL_contactsGroupInfo", Integer.valueOf(constructor2)));
                }
                return null;
            }
            TL_contactsGroupInfo result = new TL_contactsGroupInfo();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.group_id = stream.readInt32(exception);
            this.title = stream.readString(exception);
            this.date = stream.readInt32(exception);
            this.order_id = stream.readInt32(exception);
        }
    }

    public static class TL_contactGroupOrderInfo extends TLObject {
        public static int constructor = -343255219;
        public int group_id;
        public int order_id;

        public static TL_contactGroupOrderInfo TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (constructor != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in TL_contactGroupOrderInfo", Integer.valueOf(constructor2)));
                }
                return null;
            }
            TL_contactGroupOrderInfo result = new TL_contactGroupOrderInfo();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.group_id);
            stream.writeInt32(this.order_id);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.group_id = stream.readInt32(exception);
            this.order_id = stream.readInt32(exception);
        }
    }

    public static class TL_createGroup extends TLObject {
        public static int constructor = 1821575564;
        public long random_id;
        public String title;
        public List<TLRPC.InputUser> users = new ArrayList();

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TL_contactsGroupInfo.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt64(this.random_id);
            stream.writeString(this.title);
            stream.writeInt32(481674261);
            stream.writeInt32(this.users.size());
            for (TLRPC.InputUser inputUser : this.users) {
                inputUser.serializeToStream(stream);
            }
        }
    }

    public static class TL_setUserGroup extends TLObject {
        public static int constructor = -864626311;
        public int group_id;
        public List<TLRPC.InputPeer> users = new ArrayList();

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Bool.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.group_id);
            stream.writeInt32(481674261);
            stream.writeInt32(this.users.size());
            for (TLRPC.InputPeer inputPeer : this.users) {
                inputPeer.serializeToStream(stream);
            }
        }
    }

    public static class TL_inputPeerUserChange extends TLRPC.InputPeer {
        public static int constructor = -159164364;
        public String fist_name;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.user_id = stream.readInt32(exception);
            this.access_hash = stream.readInt64(exception);
            this.fist_name = stream.readString(exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.user_id);
            stream.writeInt64(this.access_hash);
            stream.writeString(this.fist_name);
        }
    }

    public static class TL_changeGroupName extends TLObject {
        public static int constructor = 771543448;
        public int group_id;
        public String title;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Bool.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.group_id);
            stream.writeString(this.title);
        }
    }

    public static class TL_changeGroupOrder extends TLObject {
        public static int constructor = -1084410942;
        public List<TL_contactGroupOrderInfo> group_orders = new ArrayList();

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Bool.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(481674261);
            stream.writeInt32(this.group_orders.size());
            for (TL_contactGroupOrderInfo info : this.group_orders) {
                info.serializeToStream(stream);
            }
        }
    }

    public static class TL_deleteGroup extends TLObject {
        public static int constructor = 2014246598;
        public int group_id;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Bool.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.group_id);
        }
    }

    public static class TL_deleteGroups extends TLObject {
        public static int constructor = -1435759061;
        public List<Integer> group_ids = new ArrayList();

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Bool.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(481674261);
            stream.writeInt32(this.group_ids.size());
            for (Integer i : this.group_ids) {
                stream.writeInt32(i.intValue());
            }
        }
    }

    public static class TL_updateContactGroups extends TLRPC.Update {
        public static int constructor = 321170402;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
        }
    }

    public static class NotifyMsg extends TLObject {
        public int seq;

        public static NotifyMsg TLdeserialize(AbstractSerializedData stream, int constructor, boolean exception) {
            NotifyMsg result = null;
            if (constructor == 932826098) {
                result = new NotifyMsgInputMedia();
            } else if (constructor == 1705511233) {
                result = new NotifyMsgMedia();
            } else if (constructor == 1907532607) {
                result = new NotifyMsgText();
            }
            if (result == null && exception) {
                throw new RuntimeException(String.format("can't parse magic %x in InputMedia", Integer.valueOf(constructor)));
            }
            if (result != null) {
                result.readParams(stream, exception);
            }
            return result;
        }
    }

    public static class NotifyMsgText extends NotifyMsg {
        public int constructor = 1907532607;
        public String msg;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(this.constructor);
            stream.writeInt32(this.seq);
            stream.writeString(this.msg);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.seq = stream.readInt32(exception);
            this.msg = stream.readString(exception);
        }
    }

    public static class NotifyMsgInputMedia extends NotifyMsg {
        public int constructor = 932826098;
        public TLRPC.InputMedia media;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(this.constructor);
            stream.writeInt32(this.seq);
            TLRPC.InputMedia inputMedia = this.media;
            if (inputMedia != null) {
                inputMedia.serializeToStream(stream);
            }
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.seq = stream.readInt32(exception);
            this.media = TLRPC.InputMedia.TLdeserialize(stream, stream.readInt32(exception), exception);
        }
    }

    public static class NotifyMsgMedia extends NotifyMsg {
        public int constructor = 1705511233;
        public TLRPC.MessageMedia media;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(this.constructor);
            stream.writeInt32(this.seq);
            TLRPC.MessageMedia messageMedia = this.media;
            if (messageMedia != null) {
                messageMedia.serializeToStream(stream);
            }
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.seq = stream.readInt32(exception);
            this.media = TLRPC.MessageMedia.TLdeserialize(stream, stream.readInt32(exception), exception);
        }
    }

    public static class TL_EditMessageMedia extends TLRPC.Updates {
        public int constructor = 1364895755;
        public int id;
        public TLRPC.InputMedia media;
        public TLRPC.InputPeer peer;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(this.constructor);
            this.peer.serializeToStream(stream);
            stream.writeInt32(this.id);
            this.media.serializeToStream(stream);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.peer = TLRPC.InputPeer.TLdeserialize(stream, stream.readInt32(exception), exception);
            this.id = stream.readInt32(exception);
            this.media = TLRPC.InputMedia.TLdeserialize(stream, stream.readInt32(exception), exception);
        }
    }

    public static class InputMediaSysNotify extends TLRPC.InputMedia {
        public int business_code;
        public TLRPC.TL_dataJSON data;
        public int source_code;
        public int constructor = 1333424555;
        public ArrayList<NotifyMsg> texts = new ArrayList<>();
        public ArrayList<NotifyMsg> medias = new ArrayList<>();
        public ArrayList<Integer> users = new ArrayList<>();

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(this.constructor);
            stream.writeInt32(this.source_code);
            stream.writeInt32(this.business_code);
            if (this.texts != null) {
                stream.writeInt32(481674261);
                int size = this.texts.size();
                stream.writeInt32(size);
                for (NotifyMsg notifyMsg : this.texts) {
                    notifyMsg.serializeToStream(stream);
                }
            }
            if (this.medias != null) {
                stream.writeInt32(481674261);
                int size2 = this.medias.size();
                stream.writeInt32(size2);
                for (NotifyMsg notifyMsg2 : this.medias) {
                    notifyMsg2.serializeToStream(stream);
                }
            }
            if (this.users != null) {
                stream.writeInt32(481674261);
                int count = this.users.size();
                stream.writeInt32(count);
                for (int i = 0; i < count; i++) {
                    stream.writeInt32(this.users.get(i).intValue());
                }
            }
            this.data.serializeToStream(stream);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.source_code = stream.readInt32(exception);
            this.business_code = stream.readInt32(exception);
            int magic = stream.readInt32(exception);
            if (magic != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic)));
                }
                return;
            }
            int count = stream.readInt32(exception);
            for (int a = 0; a < count; a++) {
                this.texts.add(NotifyMsg.TLdeserialize(stream, stream.readInt32(exception), exception));
            }
            int magic2 = stream.readInt32(exception);
            if (magic2 != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic2)));
                }
                return;
            }
            int count2 = stream.readInt32(exception);
            for (int a2 = 0; a2 < count2; a2++) {
                NotifyMsg object = NotifyMsg.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (object == null) {
                    return;
                }
                this.medias.add(object);
            }
            int magic3 = stream.readInt32(exception);
            if (magic3 != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic3)));
                }
                return;
            }
            int count3 = stream.readInt32(exception);
            for (int a3 = 0; a3 < count3; a3++) {
                Integer id = Integer.valueOf(stream.readInt32(exception));
                if (id == null && id.intValue() == 0) {
                    return;
                }
                this.users.add(id);
            }
            int a4 = stream.readInt32(exception);
            this.data = TLRPC.TL_dataJSON.TLdeserialize(stream, a4, exception);
        }
    }

    public static class TL_messageMediaSysNotify extends TLRPC.MessageMedia {
        public static int constructor = 1352198849;
        public int business_code;
        public TLRPC.TL_dataJSON data;
        public int source_code;
        public ArrayList<NotifyMsg> texts = new ArrayList<>();
        public ArrayList<NotifyMsg> medias = new ArrayList<>();
        public ArrayList<Integer> users = new ArrayList<>();

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt32(this.source_code);
            stream.writeInt32(this.business_code);
            if (this.texts != null) {
                stream.writeInt32(481674261);
                int size = this.texts.size();
                stream.writeInt32(size);
                for (NotifyMsg notifyMsg : this.texts) {
                    notifyMsg.serializeToStream(stream);
                }
            }
            if (this.medias != null) {
                stream.writeInt32(481674261);
                int size2 = this.medias.size();
                stream.writeInt32(size2);
                for (NotifyMsg notifyMsg2 : this.medias) {
                    notifyMsg2.serializeToStream(stream);
                }
            }
            if (this.users != null) {
                stream.writeInt32(481674261);
                int count = this.users.size();
                stream.writeInt32(count);
                for (int i = 0; i < count; i++) {
                    stream.writeInt32(this.users.get(i).intValue());
                }
            }
            this.data.serializeToStream(stream);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.source_code = stream.readInt32(exception);
            this.business_code = stream.readInt32(exception);
            int magic = stream.readInt32(exception);
            if (magic != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic)));
                }
                return;
            }
            int count = stream.readInt32(exception);
            for (int a = 0; a < count; a++) {
                this.texts.add(NotifyMsg.TLdeserialize(stream, stream.readInt32(exception), exception));
            }
            int magic2 = stream.readInt32(exception);
            if (magic2 != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic2)));
                }
                return;
            }
            int count2 = stream.readInt32(exception);
            for (int a2 = 0; a2 < count2; a2++) {
                NotifyMsg object = NotifyMsg.TLdeserialize(stream, stream.readInt32(exception), exception);
                if (object == null) {
                    return;
                }
                this.medias.add(object);
            }
            int magic3 = stream.readInt32(exception);
            if (magic3 != 481674261) {
                if (exception) {
                    throw new RuntimeException(String.format("wrong Vector magic, got %x", Integer.valueOf(magic3)));
                }
                return;
            }
            int count3 = stream.readInt32(exception);
            for (int a3 = 0; a3 < count3; a3++) {
                Integer id = Integer.valueOf(stream.readInt32(exception));
                if (id == null && id.intValue() == 0) {
                    return;
                }
                this.users.add(id);
            }
            int a4 = stream.readInt32(exception);
            this.data = TLRPC.TL_dataJSON.TLdeserialize(stream, a4, exception);
        }
    }
}
