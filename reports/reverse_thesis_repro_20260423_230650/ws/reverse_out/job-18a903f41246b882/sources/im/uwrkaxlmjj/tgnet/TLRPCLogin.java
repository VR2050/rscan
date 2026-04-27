package im.uwrkaxlmjj.tgnet;

import im.uwrkaxlmjj.tgnet.TLRPC;

/* JADX INFO: loaded from: classes2.dex */
public class TLRPCLogin {

    public static class TL_auth_SignUpV1 extends TLObject {
        public static int constructor = -419627884;
        public int birthday;
        public String company_tag = "Sbcc";
        public TLRPC.TL_dataJSON extend;
        public String first_name;
        public int flags;
        public String password_hash;
        public String phone_uuid;
        public TLRPC.InputFile photo;
        public int sex;
        public String user_name;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.auth_Authorization.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            int i;
            stream.writeInt32(constructor);
            if (this.extend != null) {
                i = this.flags | 2;
                this.flags = i;
            } else {
                i = this.flags & (-3);
            }
            this.flags = i;
            stream.writeInt32(i);
            stream.writeString(this.company_tag);
            stream.writeString(this.user_name);
            stream.writeString(this.password_hash);
            stream.writeString(this.first_name);
            TLRPC.InputFile inputFile = this.photo;
            if (inputFile != null) {
                inputFile.serializeToStream(stream);
            }
            stream.writeInt32(this.sex);
            stream.writeInt32(this.birthday);
            TLRPC.TL_dataJSON tL_dataJSON = this.extend;
            if (tL_dataJSON != null) {
                tL_dataJSON.serializeToStream(stream);
            }
            stream.writeString(this.phone_uuid);
        }
    }

    public static class TL_auth_SignAuto2 extends TLObject {
        public static int constructor = 597896548;
        public String company_tag = "Sbcc";
        public String device_new;
        public String device_old;
        public String ip;
        public String phone_uuid;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.auth_Authorization.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeString(this.company_tag);
            stream.writeString(this.device_old);
            stream.writeString(this.device_new);
            stream.writeString(this.phone_uuid);
            stream.writeString(this.ip);
        }

        public String toString() {
            return "TL_auth_SignAuto2{company_tag='" + this.company_tag + "', device_old='" + this.device_old + "', device_new='" + this.device_new + "'}";
        }
    }

    public static class TL_auth_signUpBind extends TLObject {
        public static int constructor = -731492206;
        public String company;
        public String device;
        public TLRPC.TL_dataJSON extend;
        public int flag;
        public int userId;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            int i = this.extend != null ? this.flag | 2 : this.flag & (-3);
            this.flag = i;
            stream.writeInt32(i);
            stream.writeInt32(this.userId);
            stream.writeString(this.device);
            stream.writeString(this.company);
            TLRPC.TL_dataJSON tL_dataJSON = this.extend;
            if (tL_dataJSON != null) {
                tL_dataJSON.serializeToStream(stream);
            }
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Bool.TLdeserialize(stream, constructor2, exception);
        }
    }

    public static class TL_auth_LoginPasswordSet extends TLObject {
        public static int constructor = -1129483055;
        public String password;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Bool.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeString(this.password);
        }
    }

    public static class TL_auth_LoginPasswordReset extends TLObject {
        public static int constructor = -1625767364;
        public String password_hash;
        public String phone_number;
        public String sms_code;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Bool.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeString(this.phone_number);
            stream.writeString(this.password_hash);
            stream.writeString(this.sms_code);
        }
    }

    public static class TL_auth_LoginPasswordReset_v2 extends TLObject {
        public static int constructor = 671418343;
        public String current_pwd_hash;
        public String new_pwd_hash;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Bool.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeString(this.current_pwd_hash);
            stream.writeString(this.new_pwd_hash);
        }
    }

    public static class TL_auth_SignInByPassword extends TLObject {
        public String company_tag = "Sbcc";
        public String ip;
        public String password_hash;
        public String phone_uuid;
        public String user_name;
        public static int constructor_old = 1385179147;
        public static int constructor = -767430627;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.auth_Authorization.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeString(this.company_tag);
            stream.writeString(this.user_name);
            stream.writeString(this.password_hash);
            stream.writeString(this.phone_uuid);
            stream.writeString(this.ip);
        }
    }

    public static class TL_auth_SendCode extends TLObject {
        public static int constructor = -411209816;
        public String api_hash;
        public int api_id;
        public String phone_number;
        public TLRPC.TL_codeSettings settings;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.TL_auth_sentCode.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeString(this.phone_number);
            stream.writeInt32(this.api_id);
            stream.writeString(this.api_hash);
            this.settings.serializeToStream(stream);
        }
    }

    public static class TL_authBySMS extends TLObject {
        public static int constructor = 2004171853;
        public int auth_type;
        public String phone_code;
        public String phone_code_hash;
        public String phone_number;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TL_authBySMSResponse.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeString(this.phone_number);
            stream.writeString(this.phone_code);
            stream.writeString(this.phone_code_hash);
            stream.writeInt32(this.auth_type);
        }
    }

    public static class TL_authBySMSResponse extends TLObject {
        public static int constructor = 1046687378;
        public String token;

        public static TL_authBySMSResponse TLdeserialize(AbstractSerializedData stream, int constructor2, boolean exception) {
            if (constructor != constructor2) {
                if (exception) {
                    throw new RuntimeException(String.format("can't parse magic %x in TL_auth_CheckVerifyCodeResponse", Integer.valueOf(constructor2)));
                }
                return null;
            }
            TL_authBySMSResponse result = new TL_authBySMSResponse();
            result.readParams(stream, exception);
            return result;
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            this.token = stream.readString(exception);
        }
    }

    public static class TL_account_setUserDetail extends TLObject {
        public static int constructor = 798490748;
        public int birthday;
        public TLRPC.TL_dataJSON extend;
        public String first_name;
        public int flags;
        public TLRPC.InputFile photo;
        public int sex;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.UserFull.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            int i = this.photo != null ? this.flags | 1 : this.flags & (-2);
            this.flags = i;
            int i2 = this.extend != null ? i | 2 : i & (-3);
            this.flags = i2;
            stream.writeInt32(i2);
            stream.writeString(this.first_name);
            TLRPC.InputFile inputFile = this.photo;
            if (inputFile != null) {
                inputFile.serializeToStream(stream);
            }
            stream.writeInt32(this.sex);
            stream.writeInt32(this.birthday);
            TLRPC.TL_dataJSON tL_dataJSON = this.extend;
            if (tL_dataJSON != null) {
                tL_dataJSON.serializeToStream(stream);
            }
        }
    }

    public static class TL_account_updateUserDetail extends TLObject {
        public static int constructor = 2055920701;
        public int birthday;
        public TLRPC.TL_dataJSON extend;
        public int flags;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.UserFull.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            int i = this.extend != null ? this.flags | 1 : this.flags & (-2);
            this.flags = i;
            stream.writeInt32(i);
            stream.writeInt32(this.birthday);
            TLRPC.TL_dataJSON tL_dataJSON = this.extend;
            if (tL_dataJSON != null) {
                tL_dataJSON.serializeToStream(stream);
            }
        }
    }

    public static class TL_GestureCodeSet extends TLObject {
        public static int constructor = 655081242;
        public String auth_token;
        public String gesture_code;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Bool.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeString(this.gesture_code);
            stream.writeString(this.auth_token);
        }
    }

    public static class TL_GestureCodeCheck extends TLObject {
        public static int constructor = -1540008826;
        public String gesture_code;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public TLObject deserializeResponse(AbstractSerializedData stream, int constructor2, boolean exception) {
            return TLRPC.Bool.TLdeserialize(stream, constructor2, exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeString(this.gesture_code);
        }
    }
}
