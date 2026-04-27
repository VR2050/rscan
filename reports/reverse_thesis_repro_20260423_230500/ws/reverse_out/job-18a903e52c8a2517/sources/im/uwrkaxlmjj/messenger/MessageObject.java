package im.uwrkaxlmjj.messenger;

import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.text.Layout;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.style.ClickableSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.ImageSpan;
import android.text.style.URLSpan;
import android.text.util.Linkify;
import android.util.Base64;
import android.util.SparseArray;
import androidx.recyclerview.widget.ItemTouchHelper;
import com.google.android.exoplayer2.util.MimeTypes;
import com.king.zxing.util.CodeUtils;
import com.king.zxing.util.LogUtils;
import im.uwrkaxlmjj.messenger.Emoji;
import im.uwrkaxlmjj.phoneformat.PhoneFormat;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.tgnet.TLRPCRedpacket;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.TextStyleSpan;
import im.uwrkaxlmjj.ui.components.URLSpanNoUnderlineBold;
import im.uwrkaxlmjj.ui.hui.sysnotify.SysNotifyAtTextClickableSpan;
import im.uwrkaxlmjj.ui.utils.number.MoneyUtil;
import im.uwrkaxlmjj.ui.utils.number.NumberUtil;
import java.io.BufferedReader;
import java.io.File;
import java.io.StringReader;
import java.math.BigDecimal;
import java.net.URLEncoder;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.regex.Pattern;

/* JADX INFO: loaded from: classes2.dex */
public class MessageObject {
    private static final int LINES_PER_BLOCK = 10;
    public static final int MESSAGE_SEND_STATE_EDITING = 3;
    public static final int MESSAGE_SEND_STATE_SENDING = 1;
    public static final int MESSAGE_SEND_STATE_SEND_ERROR = 2;
    public static final int MESSAGE_SEND_STATE_SENT = 0;
    public static final int POSITION_FLAG_BOTTOM = 8;
    public static final int POSITION_FLAG_LEFT = 1;
    public static final int POSITION_FLAG_RIGHT = 2;
    public static final int POSITION_FLAG_TOP = 4;
    public static final int TYPE_ANIMATED_STICKER = 15;
    public static final int TYPE_CARD = 103;
    public static final int TYPE_LIVE = 207;
    public static final int TYPE_PAYBILL = 104;
    public static final int TYPE_POLL = 17;
    public static final int TYPE_REDPKG = 101;
    public static final int TYPE_ROUND_VIDEO = 5;
    public static final int TYPE_STICKER = 13;
    public static final int TYPE_SYSTEM_NOTIFY = 105;
    public static final int TYPE_TRANSF = 102;
    static final String[] excludeWords = {" vs. ", " vs ", " versus ", " ft. ", " ft ", " featuring ", " feat. ", " feat ", " presents ", " pres. ", " pres ", " and ", " & ", " . "};
    public static Pattern instagramUrlPattern;
    public static Pattern urlPattern;
    public static Pattern videoTimeUrlPattern;
    public boolean attachPathExists;
    public int audioPlayerDuration;
    public float audioProgress;
    public int audioProgressMs;
    public int audioProgressSec;
    public StringBuilder botButtonsLayout;
    public float bufferedProgress;
    public boolean cancelEditing;
    public CharSequence caption;
    public int contentType;
    public int currentAccount;
    public TLRPC.TL_channelAdminLogEvent currentEvent;
    public String customReplyName;
    public String dateKey;
    public Delegate delegate;
    public boolean deleted;
    public CharSequence editingMessage;
    public ArrayList<TLRPC.MessageEntity> editingMessageEntities;
    public TLRPC.Document emojiAnimatedSticker;
    public String emojiAnimatedStickerColor;
    private int emojiOnlyCount;
    ArrayList<TLRPC.MessageEntity> entitiesCopy;
    public long eventId;
    public float forceSeekTo;
    public boolean forceUpdate;
    private float generatedWithDensity;
    private int generatedWithMinSize;
    public float gifState;
    public boolean hadAnimationNotReadyLoading;
    public boolean hasRtl;
    public boolean isDateObject;
    public boolean isRestrictedMessage;
    private int isRoundVideoCached;
    public int lastLineWidth;
    private boolean layoutCreated;
    public int linesCount;
    public CharSequence linkDescription;
    public boolean localChannel;
    public boolean localEdit;
    public long localGroupId;
    public String localName;
    public long localSentGroupId;
    public int localType;
    public String localUserName;
    public boolean mediaExists;
    public TLRPC.Message messageOwner;
    public CharSequence messageText;
    public String monthKey;
    public ArrayList<TLRPC.PhotoSize> photoThumbs;
    public ArrayList<TLRPC.PhotoSize> photoThumbs2;
    public TLObject photoThumbsObject;
    public TLObject photoThumbsObject2;
    public long pollLastCheckTime;
    public boolean pollVisibleOnScreen;
    public String previousAttachPath;
    public String previousCaption;
    public ArrayList<TLRPC.MessageEntity> previousCaptionEntities;
    public TLRPC.MessageMedia previousMedia;
    public MessageObject replyMessageObject;
    public boolean resendAsIs;
    public boolean scheduled;
    public int textHeight;
    public ArrayList<TextLayoutBlock> textLayoutBlocks;
    public int textWidth;
    public float textXOffset;
    public int transHeight;
    public int transWidth;
    public int type;
    public boolean useCustomPhoto;
    public CharSequence vCardData;
    public VideoEditedInfo videoEditedInfo;
    public boolean viewsReloaded;
    public int wantedBotKeyboardWidth;

    public interface Delegate {
        void onClickRed();
    }

    public static class VCardData {
        private String company;
        private ArrayList<String> emails = new ArrayList<>();
        private ArrayList<String> phones = new ArrayList<>();

        public static CharSequence parse(String data) {
            String[] args;
            boolean finished;
            byte[] bytes;
            try {
                BufferedReader bufferedReader = new BufferedReader(new StringReader(data));
                String pendingLine = null;
                boolean finished2 = false;
                VCardData currentData = null;
                while (true) {
                    String originalLine = bufferedReader.readLine();
                    String line = originalLine;
                    if (originalLine != null) {
                        if (!originalLine.startsWith("PHOTO")) {
                            if (originalLine.indexOf(58) >= 0) {
                                if (originalLine.startsWith("BEGIN:VCARD")) {
                                    currentData = new VCardData();
                                } else if (originalLine.startsWith("END:VCARD") && currentData != null) {
                                    finished2 = true;
                                }
                            }
                            if (pendingLine != null) {
                                line = pendingLine + line;
                                pendingLine = null;
                            }
                            int i = 0;
                            if (line.contains("=QUOTED-PRINTABLE") && line.endsWith("=")) {
                                pendingLine = line.substring(0, line.length() - 1);
                            } else {
                                int idx = line.indexOf(LogUtils.COLON);
                                if (idx >= 0) {
                                    args = new String[]{line.substring(0, idx), line.substring(idx + 1).trim()};
                                } else {
                                    args = new String[]{line.trim()};
                                }
                                if (args.length < 2 || currentData == null) {
                                    finished = finished2;
                                } else if (args[0].startsWith("ORG")) {
                                    String nameEncoding = null;
                                    String nameCharset = null;
                                    String[] params = args[0].split(";");
                                    int length = params.length;
                                    while (i < length) {
                                        String param = params[i];
                                        String[] args2 = param.split("=");
                                        int idx2 = idx;
                                        boolean finished3 = finished2;
                                        if (args2.length == 2) {
                                            if (args2[0].equals("CHARSET")) {
                                                nameCharset = args2[1];
                                            } else if (args2[0].equals("ENCODING")) {
                                                nameEncoding = args2[1];
                                            }
                                        }
                                        i++;
                                        idx = idx2;
                                        finished2 = finished3;
                                    }
                                    finished = finished2;
                                    currentData.company = args[1];
                                    if (nameEncoding != null && nameEncoding.equalsIgnoreCase("QUOTED-PRINTABLE") && (bytes = AndroidUtilities.decodeQuotedPrintable(AndroidUtilities.getStringBytes(currentData.company))) != null && bytes.length != 0) {
                                        String decodedName = new String(bytes, nameCharset);
                                        currentData.company = decodedName;
                                    }
                                    currentData.company = currentData.company.replace(';', ' ');
                                } else {
                                    finished = finished2;
                                    if (args[0].startsWith("TEL")) {
                                        if (args[1].length() > 0) {
                                            currentData.phones.add(args[1]);
                                        }
                                    } else if (args[0].startsWith("EMAIL")) {
                                        String email = args[1];
                                        if (email.length() > 0) {
                                            currentData.emails.add(email);
                                        }
                                    }
                                }
                                finished2 = finished;
                            }
                        }
                    } else {
                        try {
                            break;
                        } catch (Exception e) {
                            FileLog.e(e);
                        }
                    }
                }
                bufferedReader.close();
                if (finished2) {
                    StringBuilder result = new StringBuilder();
                    for (int a = 0; a < currentData.phones.size(); a++) {
                        if (result.length() > 0) {
                            result.append('\n');
                        }
                        String phone = currentData.phones.get(a);
                        if (phone.contains("#") || phone.contains("*")) {
                            result.append(phone);
                        } else {
                            result.append(PhoneFormat.getInstance().format(phone));
                        }
                    }
                    for (int a2 = 0; a2 < currentData.emails.size(); a2++) {
                        if (result.length() > 0) {
                            result.append('\n');
                        }
                        result.append(PhoneFormat.getInstance().format(currentData.emails.get(a2)));
                    }
                    if (!TextUtils.isEmpty(currentData.company)) {
                        if (result.length() > 0) {
                            result.append('\n');
                        }
                        result.append(currentData.company);
                    }
                    return result;
                }
                return null;
            } catch (Throwable th) {
                return null;
            }
        }
    }

    public static class TextLayoutBlock {
        public int charactersEnd;
        public int charactersOffset;
        public byte directionFlags;
        public int height;
        public int heightByOffset;
        public StaticLayout textLayout;
        public float textYOffset;

        public boolean isRtl() {
            byte b = this.directionFlags;
            return (b & 1) != 0 && (b & 2) == 0;
        }
    }

    public static class GroupedMessagePosition {
        public float aspectRatio;
        public boolean edge;
        public int flags;
        public boolean last;
        public int leftSpanOffset;
        public byte maxX;
        public byte maxY;
        public byte minX;
        public byte minY;
        public float ph;
        public int pw;
        public float[] siblingHeights;
        public int spanSize;

        public void set(int minX, int maxX, int minY, int maxY, int w, float h, int flags) {
            this.minX = (byte) minX;
            this.maxX = (byte) maxX;
            this.minY = (byte) minY;
            this.maxY = (byte) maxY;
            this.pw = w;
            this.spanSize = w;
            this.ph = h;
            this.flags = (byte) flags;
        }
    }

    public static class GroupedMessages {
        public long groupId;
        public boolean hasSibling;
        public ArrayList<MessageObject> messages = new ArrayList<>();
        public ArrayList<GroupedMessagePosition> posArray = new ArrayList<>();
        public HashMap<MessageObject, GroupedMessagePosition> positions = new HashMap<>();
        private int maxSizeWidth = CodeUtils.DEFAULT_REQ_HEIGHT;
        private int firstSpanAdditionalSize = ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION;

        public int getMaxSizeWidth() {
            return this.maxSizeWidth;
        }

        private class MessageGroupedLayoutAttempt {
            public float[] heights;
            public int[] lineCounts;

            public MessageGroupedLayoutAttempt(int i1, int i2, float f1, float f2) {
                this.lineCounts = new int[]{i1, i2};
                this.heights = new float[]{f1, f2};
            }

            public MessageGroupedLayoutAttempt(int i1, int i2, int i3, float f1, float f2, float f3) {
                this.lineCounts = new int[]{i1, i2, i3};
                this.heights = new float[]{f1, f2, f3};
            }

            public MessageGroupedLayoutAttempt(int i1, int i2, int i3, int i4, float f1, float f2, float f3, float f4) {
                this.lineCounts = new int[]{i1, i2, i3, i4};
                this.heights = new float[]{f1, f2, f3, f4};
            }
        }

        private float multiHeight(float[] array, int start, int end) {
            float sum = 0.0f;
            for (int a = start; a < end; a++) {
                sum += array[a];
            }
            int a2 = this.maxSizeWidth;
            return a2 / sum;
        }

        /* JADX WARN: Removed duplicated region for block: B:147:0x06e2  */
        /* JADX WARN: Removed duplicated region for block: B:234:0x08f7  */
        /* JADX WARN: Removed duplicated region for block: B:340:0x09e8 A[SYNTHETIC] */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void calculate() {
            /*
                Method dump skipped, instruction units count: 2537
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessageObject.GroupedMessages.calculate():void");
        }
    }

    public MessageObject(int accountNum, TLRPC.Message message, String formattedMessage, String name, String userName, boolean localMessage, boolean isChannel, boolean edit) {
        this.type = 1000;
        this.forceSeekTo = -1.0f;
        this.entitiesCopy = new ArrayList<>();
        this.localType = localMessage ? 2 : 1;
        this.currentAccount = accountNum;
        this.localName = name;
        this.localUserName = userName;
        this.messageText = formattedMessage;
        this.messageOwner = message;
        this.localChannel = isChannel;
        this.localEdit = edit;
    }

    public MessageObject(int accountNum, TLRPC.Message message, AbstractMap<Integer, TLRPC.User> users, boolean generateLayout) {
        this(accountNum, message, users, (AbstractMap<Integer, TLRPC.Chat>) null, generateLayout);
    }

    public MessageObject(int accountNum, TLRPC.Message message, SparseArray<TLRPC.User> users, boolean generateLayout) {
        this(accountNum, message, users, (SparseArray<TLRPC.Chat>) null, generateLayout);
    }

    public MessageObject(int accountNum, TLRPC.Message message, boolean generateLayout) {
        this(accountNum, message, null, null, null, null, null, generateLayout, 0L);
    }

    public MessageObject(int accountNum, TLRPC.Message message, MessageObject replyToMessage, boolean generateLayout) {
        this(accountNum, message, replyToMessage, null, null, null, null, generateLayout, 0L);
    }

    public MessageObject(int accountNum, TLRPC.Message message, AbstractMap<Integer, TLRPC.User> users, AbstractMap<Integer, TLRPC.Chat> chats, boolean generateLayout) {
        this(accountNum, message, users, chats, generateLayout, 0L);
    }

    public MessageObject(int accountNum, TLRPC.Message message, SparseArray<TLRPC.User> users, SparseArray<TLRPC.Chat> chats, boolean generateLayout) {
        this(accountNum, message, null, null, null, users, chats, generateLayout, 0L);
    }

    public MessageObject(int accountNum, TLRPC.Message message, AbstractMap<Integer, TLRPC.User> users, AbstractMap<Integer, TLRPC.Chat> chats, boolean generateLayout, long eid) {
        this(accountNum, message, null, users, chats, null, null, generateLayout, eid);
    }

    public MessageObject(int accountNum, TLRPC.Message message, MessageObject replyToMessage, AbstractMap<Integer, TLRPC.User> users, AbstractMap<Integer, TLRPC.Chat> chats, SparseArray<TLRPC.User> sUsers, SparseArray<TLRPC.Chat> sChats, boolean generateLayout, long eid) {
        TLRPC.User fromUser;
        int[] iArr;
        boolean z;
        int i;
        TextPaint paint;
        this.type = 1000;
        this.forceSeekTo = -1.0f;
        this.entitiesCopy = new ArrayList<>();
        Theme.createChatResources(null, true);
        this.currentAccount = accountNum;
        this.messageOwner = message;
        this.replyMessageObject = replyToMessage;
        this.eventId = eid;
        if (message.replyMessage != null) {
            this.replyMessageObject = new MessageObject(this.currentAccount, message.replyMessage, null, users, chats, sUsers, sChats, false, eid);
        }
        TLRPC.User fromUser2 = null;
        if (message.from_id <= 0) {
            fromUser = null;
        } else {
            if (users != null) {
                TLRPC.User fromUser3 = users.get(Integer.valueOf(message.from_id));
                fromUser2 = fromUser3;
            } else if (sUsers != null) {
                TLRPC.User fromUser4 = sUsers.get(message.from_id);
                fromUser2 = fromUser4;
            }
            if (fromUser2 != null) {
                fromUser = fromUser2;
            } else {
                TLRPC.User fromUser5 = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(message.from_id));
                fromUser = fromUser5;
            }
        }
        updateMessageText(users, chats, sUsers, sChats);
        if (isMediaEmpty()) {
            i = 1;
            iArr = null;
            z = generateLayout;
            this.messageText = updateMetionText(this.messageText, this.messageOwner.entities, users, chats, sUsers, sChats);
        } else {
            iArr = null;
            z = generateLayout;
            i = 1;
        }
        setType();
        measureInlineBotButtons();
        Calendar rightNow = new GregorianCalendar();
        rightNow.setTimeInMillis(((long) this.messageOwner.date) * 1000);
        int dateDay = rightNow.get(6);
        int dateYear = rightNow.get(i);
        int dateMonth = rightNow.get(2);
        Object[] objArr = new Object[3];
        objArr[0] = Integer.valueOf(dateYear);
        objArr[i] = Integer.valueOf(dateMonth);
        objArr[2] = Integer.valueOf(dateDay);
        this.dateKey = String.format("%d_%02d_%02d", objArr);
        Object[] objArr2 = new Object[2];
        objArr2[0] = Integer.valueOf(dateYear);
        objArr2[i] = Integer.valueOf(dateMonth);
        this.monthKey = String.format("%d_%02d", objArr2);
        createMessageSendInfo();
        generateCaption();
        if (z) {
            if (this.messageOwner.media instanceof TLRPC.TL_messageMediaGame) {
                paint = Theme.chat_msgGameTextPaint;
            } else {
                paint = Theme.chat_msgTextPaint;
            }
            int[] emojiOnly = SharedConfig.allowBigEmoji ? new int[i] : iArr;
            this.messageText = Emoji.replaceEmoji(this.messageText, paint.getFontMetricsInt(), AndroidUtilities.dp(20.0f), false, emojiOnly);
            checkEmojiOnly(emojiOnly);
            this.emojiAnimatedSticker = null;
            if (this.emojiOnlyCount == 1 && !(message.media instanceof TLRPC.TL_messageMediaWebPage) && message.entities.isEmpty()) {
                CharSequence emoji = this.messageText;
                int index = TextUtils.indexOf(emoji, "🏻");
                if (index >= 0) {
                    this.emojiAnimatedStickerColor = "_c1";
                    emoji = emoji.subSequence(0, index);
                } else {
                    int index2 = TextUtils.indexOf(emoji, "🏼");
                    if (index2 >= 0) {
                        this.emojiAnimatedStickerColor = "_c2";
                        emoji = emoji.subSequence(0, index2);
                    } else {
                        int index3 = TextUtils.indexOf(emoji, "🏽");
                        if (index3 >= 0) {
                            this.emojiAnimatedStickerColor = "_c3";
                            emoji = emoji.subSequence(0, index3);
                        } else {
                            int index4 = TextUtils.indexOf(emoji, "🏾");
                            if (index4 >= 0) {
                                this.emojiAnimatedStickerColor = "_c4";
                                emoji = emoji.subSequence(0, index4);
                            } else {
                                int index5 = TextUtils.indexOf(emoji, "🏿");
                                if (index5 >= 0) {
                                    this.emojiAnimatedStickerColor = "_c5";
                                    emoji = emoji.subSequence(0, index5);
                                } else {
                                    this.emojiAnimatedStickerColor = "";
                                }
                            }
                        }
                    }
                }
                this.emojiAnimatedSticker = MediaDataController.getInstance(this.currentAccount).getEmojiAnimatedSticker(emoji);
            }
            if (this.emojiAnimatedSticker != null) {
                this.type = 1000;
                if (isSticker()) {
                    this.type = 13;
                } else if (isAnimatedSticker()) {
                    this.type = 15;
                }
            } else {
                generateLayout(fromUser);
            }
        }
        this.layoutCreated = z;
        generateThumbs(false);
        checkMediaExistance();
    }

    public void renderText() {
        entityCopy(this.messageOwner.entities);
        addEntitiesToText(this.messageText, false);
    }

    private void entityCopy(ArrayList<TLRPC.MessageEntity> entities) {
        if (entities == null || entities.size() == 0) {
            return;
        }
        this.entitiesCopy.clear();
        for (TLRPC.MessageEntity entity : entities) {
            if (entity instanceof TLRPC.TL_messageEntityTextUrl) {
                TLRPC.TL_messageEntityTextUrl item = new TLRPC.TL_messageEntityTextUrl();
                item.offset = entity.offset;
                item.length = entity.length;
                item.url = entity.url;
                this.entitiesCopy.add(item);
            } else if (entity instanceof TLRPC.TL_messageEntityBotCommand) {
                TLRPC.TL_messageEntityBotCommand item2 = new TLRPC.TL_messageEntityBotCommand();
                item2.offset = entity.offset;
                item2.length = entity.length;
                this.entitiesCopy.add(item2);
            } else if (entity instanceof TLRPC.TL_messageEntityEmail) {
                TLRPC.TL_messageEntityEmail item3 = new TLRPC.TL_messageEntityEmail();
                item3.offset = entity.offset;
                item3.length = entity.length;
                this.entitiesCopy.add(item3);
            } else if (entity instanceof TLRPC.TL_messageEntityPre) {
                TLRPC.TL_messageEntityPre item4 = new TLRPC.TL_messageEntityPre();
                item4.offset = entity.offset;
                item4.length = entity.length;
                item4.language = entity.language;
                this.entitiesCopy.add(item4);
            } else if (entity instanceof TLRPC.TL_messageEntityUnknown) {
                TLRPC.TL_messageEntityUnknown item5 = new TLRPC.TL_messageEntityUnknown();
                item5.offset = entity.offset;
                item5.length = entity.length;
                this.entitiesCopy.add(item5);
            } else if (entity instanceof TLRPC.TL_messageEntityUrl) {
                TLRPC.TL_messageEntityUrl item6 = new TLRPC.TL_messageEntityUrl();
                item6.offset = entity.offset;
                item6.length = entity.length;
                this.entitiesCopy.add(item6);
            } else if (entity instanceof TLRPC.TL_messageEntityItalic) {
                TLRPC.TL_messageEntityItalic item7 = new TLRPC.TL_messageEntityItalic();
                item7.offset = entity.offset;
                item7.length = entity.length;
                this.entitiesCopy.add(item7);
            } else if (entity instanceof TLRPC.TL_messageEntityMention) {
                TLRPC.TL_messageEntityMention item8 = new TLRPC.TL_messageEntityMention();
                item8.offset = entity.offset;
                item8.length = entity.length;
                this.entitiesCopy.add(item8);
            } else if (entity instanceof TLRPC.TL_messageEntityMentionName) {
                TLRPC.TL_messageEntityMentionName item9 = new TLRPC.TL_messageEntityMentionName();
                item9.offset = entity.offset;
                item9.length = entity.length;
                item9.user_id = ((TLRPC.TL_messageEntityMentionName) entity).user_id;
                this.entitiesCopy.add(item9);
            } else if (entity instanceof TLRPC.TL_inputMessageEntityMentionName) {
                TLRPC.TL_inputMessageEntityMentionName item10 = new TLRPC.TL_inputMessageEntityMentionName();
                item10.offset = entity.offset;
                item10.length = entity.length;
                item10.user_id = ((TLRPC.TL_inputMessageEntityMentionName) entity).user_id;
                this.entitiesCopy.add(item10);
            } else if (entity instanceof TLRPC.TL_messageEntityCashtag) {
                TLRPC.TL_messageEntityCashtag item11 = new TLRPC.TL_messageEntityCashtag();
                item11.offset = entity.offset;
                item11.length = entity.length;
                this.entitiesCopy.add(item11);
            } else if (entity instanceof TLRPC.TL_messageEntityBold) {
                TLRPC.TL_messageEntityBold item12 = new TLRPC.TL_messageEntityBold();
                item12.offset = entity.offset;
                item12.length = entity.length;
                this.entitiesCopy.add(item12);
            } else if (entity instanceof TLRPC.TL_messageEntityHashtag) {
                TLRPC.TL_messageEntityHashtag item13 = new TLRPC.TL_messageEntityHashtag();
                item13.offset = entity.offset;
                item13.length = entity.length;
                this.entitiesCopy.add(item13);
            } else if (entity instanceof TLRPC.TL_messageEntityCode) {
                TLRPC.TL_messageEntityCode item14 = new TLRPC.TL_messageEntityCode();
                item14.offset = entity.offset;
                item14.length = entity.length;
                this.entitiesCopy.add(item14);
            } else if (entity instanceof TLRPC.TL_messageEntityStrike) {
                TLRPC.TL_messageEntityStrike item15 = new TLRPC.TL_messageEntityStrike();
                item15.offset = entity.offset;
                item15.length = entity.length;
                this.entitiesCopy.add(item15);
            } else if (entity instanceof TLRPC.TL_messageEntityBlockquote) {
                TLRPC.TL_messageEntityBlockquote item16 = new TLRPC.TL_messageEntityBlockquote();
                item16.offset = entity.offset;
                item16.length = entity.length;
                this.entitiesCopy.add(item16);
            } else if (entity instanceof TLRPC.TL_messageEntityUnderline) {
                TLRPC.TL_messageEntityUnderline item17 = new TLRPC.TL_messageEntityUnderline();
                item17.offset = entity.offset;
                item17.length = entity.length;
                this.entitiesCopy.add(item17);
            } else if (entity instanceof TLRPC.TL_messageEntityPhone) {
                TLRPC.TL_messageEntityPhone item18 = new TLRPC.TL_messageEntityPhone();
                item18.offset = entity.offset;
                item18.length = entity.length;
                this.entitiesCopy.add(item18);
            }
        }
    }

    public CharSequence updateMetionText(CharSequence text, ArrayList<TLRPC.MessageEntity> entities) {
        return updateMetionText(text, entities, null, null, null, null);
    }

    /* JADX WARN: Removed duplicated region for block: B:102:0x01a5  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.CharSequence updateMetionText(java.lang.CharSequence r20, java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC.MessageEntity> r21, java.util.AbstractMap<java.lang.Integer, im.uwrkaxlmjj.tgnet.TLRPC.User> r22, java.util.AbstractMap<java.lang.Integer, im.uwrkaxlmjj.tgnet.TLRPC.Chat> r23, android.util.SparseArray<im.uwrkaxlmjj.tgnet.TLRPC.User> r24, android.util.SparseArray<im.uwrkaxlmjj.tgnet.TLRPC.Chat> r25) {
        /*
            Method dump skipped, instruction units count: 829
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessageObject.updateMetionText(java.lang.CharSequence, java.util.ArrayList, java.util.AbstractMap, java.util.AbstractMap, android.util.SparseArray, android.util.SparseArray):java.lang.CharSequence");
    }

    static /* synthetic */ int lambda$updateMetionText$0(TLRPC.MessageEntity o1, TLRPC.MessageEntity o2) {
        if (o1.offset > o2.offset) {
            return 1;
        }
        if (o1.offset < o2.offset) {
            return -1;
        }
        return 0;
    }

    public SpannableStringBuilder updateMetionText2(CharSequence text, ArrayList<TLRPC.MessageEntity> entities, BaseFragment baseFragment) {
        Spannable spannable;
        URLSpan[] spans;
        byte t;
        MessageObject messageObject = this;
        if (entities == null || entities.isEmpty()) {
            return new SpannableStringBuilder(text);
        }
        Spannable spannable2 = SpannableString.valueOf(text);
        SpannableStringBuilder result = new SpannableStringBuilder("");
        URLSpan[] spans2 = (URLSpan[]) spannable2.getSpans(0, text.length(), URLSpan.class);
        ArrayList<TextStyleSpan.TextStyleRun> runs = new ArrayList<>();
        messageObject.entityCopy(entities);
        Collections.sort(messageObject.entitiesCopy, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessageObject$wn34BaMcafgYfeK4E6v1c41pg_U
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return MessageObject.lambda$updateMetionText2$1((TLRPC.MessageEntity) obj, (TLRPC.MessageEntity) obj2);
            }
        });
        int N = messageObject.entitiesCopy.size();
        for (int a = 0; a < N; a++) {
            TLRPC.MessageEntity entity = messageObject.entitiesCopy.get(a);
            if (entity.length > 0 && entity.offset >= 0 && entity.offset < text.length()) {
                if (entity.offset + entity.length > text.length()) {
                    entity.length = text.length() - entity.offset;
                }
                if (((entity instanceof TLRPC.TL_messageEntityBold) || (entity instanceof TLRPC.TL_messageEntityItalic) || (entity instanceof TLRPC.TL_messageEntityStrike) || (entity instanceof TLRPC.TL_messageEntityUnderline) || (entity instanceof TLRPC.TL_messageEntityBlockquote) || (entity instanceof TLRPC.TL_messageEntityCode) || (entity instanceof TLRPC.TL_messageEntityPre) || (entity instanceof TLRPC.TL_messageEntityMentionName) || (entity instanceof TLRPC.TL_inputMessageEntityMentionName) || (entity instanceof TLRPC.TL_messageEntityTextUrl)) && spans2 != null && spans2.length > 0) {
                    for (int b = 0; b < spans2.length; b++) {
                        if (spans2[b] != null) {
                            int start = spannable2.getSpanStart(spans2[b]);
                            int end = spannable2.getSpanEnd(spans2[b]);
                            if ((entity.offset <= start && entity.offset + entity.length >= start) || (entity.offset <= end && entity.offset + entity.length >= end)) {
                                spannable2.removeSpan(spans2[b]);
                                spans2[b] = null;
                            }
                        }
                    }
                }
                TextStyleSpan.TextStyleRun newRun = new TextStyleSpan.TextStyleRun();
                newRun.start = entity.offset;
                newRun.end = newRun.start + entity.length;
                if (entity instanceof TLRPC.TL_messageEntityStrike) {
                    newRun.flags = 8;
                } else if (entity instanceof TLRPC.TL_messageEntityUnderline) {
                    newRun.flags = 16;
                } else if (entity instanceof TLRPC.TL_messageEntityBlockquote) {
                    newRun.flags = 32;
                } else if (entity instanceof TLRPC.TL_messageEntityBold) {
                    newRun.flags = 1;
                } else if (entity instanceof TLRPC.TL_messageEntityItalic) {
                    newRun.flags = 2;
                } else if ((entity instanceof TLRPC.TL_messageEntityCode) || (entity instanceof TLRPC.TL_messageEntityPre)) {
                    newRun.flags = 4;
                } else if ((entity instanceof TLRPC.TL_messageEntityMentionName) || (entity instanceof TLRPC.TL_inputMessageEntityMentionName)) {
                    newRun.flags = 64;
                    newRun.urlEntity = entity;
                }
                int b2 = 0;
                int N2 = runs.size();
                while (b2 < N2) {
                    TextStyleSpan.TextStyleRun run = runs.get(b2);
                    if (newRun.start > run.start) {
                        if (newRun.start < run.end) {
                            if (newRun.end < run.end) {
                                TextStyleSpan.TextStyleRun r = new TextStyleSpan.TextStyleRun(newRun);
                                r.merge(run);
                                int b3 = b2 + 1;
                                runs.add(b3, r);
                                TextStyleSpan.TextStyleRun r2 = new TextStyleSpan.TextStyleRun(run);
                                r2.start = newRun.end;
                                b2 = b3 + 1;
                                N2 = N2 + 1 + 1;
                                runs.add(b2, r2);
                            } else if (newRun.end >= run.end) {
                                TextStyleSpan.TextStyleRun r3 = new TextStyleSpan.TextStyleRun(newRun);
                                r3.merge(run);
                                r3.end = run.end;
                                b2++;
                                N2++;
                                runs.add(b2, r3);
                            }
                            int temp = newRun.start;
                            newRun.start = run.end;
                            run.end = temp;
                        }
                    } else if (run.start < newRun.end) {
                        int temp2 = run.start;
                        if (newRun.end == run.end) {
                            run.merge(newRun);
                        } else if (newRun.end < run.end) {
                            TextStyleSpan.TextStyleRun r4 = new TextStyleSpan.TextStyleRun(run);
                            r4.merge(newRun);
                            r4.end = newRun.end;
                            b2++;
                            N2++;
                            runs.add(b2, r4);
                            run.start = newRun.end;
                        } else {
                            TextStyleSpan.TextStyleRun r5 = new TextStyleSpan.TextStyleRun(newRun);
                            r5.start = run.end;
                            b2++;
                            N2++;
                            runs.add(b2, r5);
                            run.merge(newRun);
                        }
                        newRun.end = temp2;
                    }
                    b2++;
                }
                if (newRun.start < newRun.end) {
                    runs.add(newRun);
                }
            }
        }
        int count = runs.size();
        byte t2 = 1;
        int a2 = 0;
        while (a2 < count) {
            TextStyleSpan.TextStyleRun run2 = runs.get(a2);
            if (run2.urlEntity instanceof TLRPC.TL_messageEntityMentionName) {
                TLRPC.User user = MessagesController.getInstance(UserConfig.selectedAccount).getUser(Integer.valueOf(((TLRPC.TL_messageEntityMentionName) run2.urlEntity).user_id));
                if (user != null) {
                    CharSequence content = text;
                    if (!TextUtils.isEmpty(result)) {
                        content = result;
                    }
                    SpannableStringBuilder builder = new SpannableStringBuilder(content);
                    String name = "@" + UserObject.getName(user) + " ";
                    builder.replace(run2.start, run2.end, (CharSequence) name);
                    int oriEnd = run2.end;
                    run2.end = run2.start + name.length();
                    spannable = spannable2;
                    spans = spans2;
                    builder.setSpan(new ForegroundColorSpan(-13915656), run2.start, run2.end, 33);
                    SysNotifyAtTextClickableSpan sysNotifyAtTextClickableSpan = new SysNotifyAtTextClickableSpan(user.id, baseFragment);
                    t = t2;
                    builder.setSpan(sysNotifyAtTextClickableSpan, run2.start, run2.end, 33);
                    int newOffset = oriEnd - run2.end;
                    int j = 0;
                    while (j < messageObject.entitiesCopy.size()) {
                        TLRPC.MessageEntity messageEntity = messageObject.entitiesCopy.get(j);
                        SysNotifyAtTextClickableSpan sysNotifyAtTextClickableSpan2 = sysNotifyAtTextClickableSpan;
                        if (messageEntity.offset >= run2.start) {
                            if (messageEntity.offset == run2.start) {
                                messageEntity.length = name.length();
                            } else {
                                messageEntity.offset -= newOffset;
                            }
                        }
                        j++;
                        messageObject = this;
                        sysNotifyAtTextClickableSpan = sysNotifyAtTextClickableSpan2;
                    }
                    for (int j2 = a2; j2 < count; j2++) {
                        TextStyleSpan.TextStyleRun nextRun = runs.get(j2);
                        nextRun.start -= newOffset;
                        nextRun.end -= newOffset;
                    }
                    result = builder;
                } else {
                    spannable = spannable2;
                    spans = spans2;
                    t = t2;
                }
            } else {
                spannable = spannable2;
                spans = spans2;
                t = t2;
            }
            a2++;
            messageObject = this;
            spannable2 = spannable;
            spans2 = spans;
            t2 = t;
        }
        if (TextUtils.isEmpty(result) && !TextUtils.isEmpty(text)) {
            SpannableStringBuilder result2 = SpannableStringBuilder.valueOf(text);
            return result2;
        }
        return result;
    }

    static /* synthetic */ int lambda$updateMetionText2$1(TLRPC.MessageEntity o1, TLRPC.MessageEntity o2) {
        if (o1.offset > o2.offset) {
            return 1;
        }
        if (o1.offset < o2.offset) {
            return -1;
        }
        return 0;
    }

    private void createDateArray(int accountNum, TLRPC.TL_channelAdminLogEvent event, ArrayList<MessageObject> messageObjects, HashMap<String, ArrayList<MessageObject>> messagesByDays) {
        ArrayList<MessageObject> dayArray = messagesByDays.get(this.dateKey);
        if (dayArray == null) {
            ArrayList<MessageObject> dayArray2 = new ArrayList<>();
            messagesByDays.put(this.dateKey, dayArray2);
            TLRPC.TL_message dateMsg = new TLRPC.TL_message();
            dateMsg.message = LocaleController.formatDateChat(event.date);
            dateMsg.id = 0;
            dateMsg.date = event.date;
            MessageObject dateObj = new MessageObject(accountNum, dateMsg, false);
            dateObj.type = 10;
            dateObj.contentType = 1;
            dateObj.isDateObject = true;
            messageObjects.add(dateObj);
        }
    }

    public void checkForScam() {
    }

    private void checkEmojiOnly(int[] emojiOnly) {
        TextPaint emojiPaint;
        int size;
        if (emojiOnly != null && emojiOnly[0] >= 1 && emojiOnly[0] <= 3) {
            int i = emojiOnly[0];
            if (i == 1) {
                emojiPaint = Theme.chat_msgTextPaintOneEmoji;
                int size2 = AndroidUtilities.dp(32.0f);
                this.emojiOnlyCount = 1;
                size = size2;
            } else if (i == 2) {
                emojiPaint = Theme.chat_msgTextPaintTwoEmoji;
                int size3 = AndroidUtilities.dp(28.0f);
                this.emojiOnlyCount = 2;
                size = size3;
            } else {
                emojiPaint = Theme.chat_msgTextPaintThreeEmoji;
                size = AndroidUtilities.dp(24.0f);
                this.emojiOnlyCount = 3;
            }
            CharSequence charSequence = this.messageText;
            Emoji.EmojiSpan[] spans = (Emoji.EmojiSpan[]) ((Spannable) charSequence).getSpans(0, charSequence.length(), Emoji.EmojiSpan.class);
            if (spans != null && spans.length > 0) {
                for (Emoji.EmojiSpan emojiSpan : spans) {
                    emojiSpan.replaceFontMetrics(emojiPaint.getFontMetricsInt(), size);
                }
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:257:0x0784  */
    /* JADX WARN: Removed duplicated region for block: B:259:0x078c  */
    /* JADX WARN: Removed duplicated region for block: B:264:0x07a0  */
    /* JADX WARN: Removed duplicated region for block: B:268:0x07a6 A[LOOP:0: B:245:0x0747->B:268:0x07a6, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:553:0x1005  */
    /* JADX WARN: Removed duplicated region for block: B:556:0x1051  */
    /* JADX WARN: Removed duplicated region for block: B:559:0x1062  */
    /* JADX WARN: Removed duplicated region for block: B:563:0x1070  */
    /* JADX WARN: Removed duplicated region for block: B:573:0x10d6  */
    /* JADX WARN: Removed duplicated region for block: B:576:0x10de  */
    /* JADX WARN: Removed duplicated region for block: B:592:0x1148 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:593:0x07c7 A[EDGE_INSN: B:593:0x07c7->B:272:0x07c7 BREAK  A[LOOP:0: B:245:0x0747->B:268:0x07a6], SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public MessageObject(int r33, im.uwrkaxlmjj.tgnet.TLRPC.TL_channelAdminLogEvent r34, java.util.ArrayList<im.uwrkaxlmjj.messenger.MessageObject> r35, java.util.HashMap<java.lang.String, java.util.ArrayList<im.uwrkaxlmjj.messenger.MessageObject>> r36, im.uwrkaxlmjj.tgnet.TLRPC.Chat r37, int[] r38) {
        /*
            Method dump skipped, instruction units count: 4425
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessageObject.<init>(int, im.uwrkaxlmjj.tgnet.TLRPC$TL_channelAdminLogEvent, java.util.ArrayList, java.util.HashMap, im.uwrkaxlmjj.tgnet.TLRPC$Chat, int[]):void");
    }

    private String getUserName(TLRPC.User user, ArrayList<TLRPC.MessageEntity> entities, int offset) {
        String name;
        if (user == null) {
            name = "";
        } else {
            String name2 = user.first_name;
            name = ContactsController.formatName(name2, user.last_name);
        }
        if (offset >= 0) {
            TLRPC.TL_messageEntityMentionName entity = new TLRPC.TL_messageEntityMentionName();
            entity.user_id = user.id;
            entity.offset = offset;
            entity.length = name.length();
            entities.add(entity);
        }
        if (TextUtils.isEmpty(user.username)) {
            return name;
        }
        if (offset >= 0) {
            TLRPC.TL_messageEntityMentionName entity2 = new TLRPC.TL_messageEntityMentionName();
            entity2.user_id = user.id;
            entity2.offset = name.length() + offset + 2;
            entity2.length = user.username.length() + 1;
            entities.add(entity2);
        }
        return String.format("%1$s (@%2$s)", name, user.username);
    }

    public void applyNewText() {
        TextPaint paint;
        if (TextUtils.isEmpty(this.messageOwner.message)) {
            return;
        }
        TLRPC.User fromUser = null;
        if (isFromUser()) {
            fromUser = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.messageOwner.from_id));
        }
        this.messageText = this.messageOwner.message;
        if (this.messageOwner.media instanceof TLRPC.TL_messageMediaGame) {
            paint = Theme.chat_msgGameTextPaint;
        } else {
            paint = Theme.chat_msgTextPaint;
        }
        int[] emojiOnly = SharedConfig.allowBigEmoji ? new int[1] : null;
        this.messageText = Emoji.replaceEmoji(this.messageText, paint.getFontMetricsInt(), AndroidUtilities.dp(20.0f), false, emojiOnly);
        checkEmojiOnly(emojiOnly);
        generateLayout(fromUser);
    }

    public void generateGameMessageText(TLRPC.User fromUser) {
        if (fromUser == null && this.messageOwner.from_id > 0) {
            fromUser = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.messageOwner.from_id));
        }
        TLRPC.TL_game game = null;
        MessageObject messageObject = this.replyMessageObject;
        if (messageObject != null && messageObject.messageOwner.media != null && this.replyMessageObject.messageOwner.media.game != null) {
            game = this.replyMessageObject.messageOwner.media.game;
        }
        if (game == null) {
            if (fromUser == null || fromUser.id != UserConfig.getInstance(this.currentAccount).getClientUserId()) {
                this.messageText = replaceWithLink(LocaleController.formatString("ActionUserScored", mpEIGo.juqQQs.esbSDO.R.string.ActionUserScored, LocaleController.formatPluralString("Points", this.messageOwner.action.score)), "un1", fromUser);
                return;
            } else {
                this.messageText = LocaleController.formatString("ActionYouScored", mpEIGo.juqQQs.esbSDO.R.string.ActionYouScored, LocaleController.formatPluralString("Points", this.messageOwner.action.score));
                return;
            }
        }
        if (fromUser == null || fromUser.id != UserConfig.getInstance(this.currentAccount).getClientUserId()) {
            this.messageText = replaceWithLink(LocaleController.formatString("ActionUserScoredInGame", mpEIGo.juqQQs.esbSDO.R.string.ActionUserScoredInGame, LocaleController.formatPluralString("Points", this.messageOwner.action.score)), "un1", fromUser);
        } else {
            this.messageText = LocaleController.formatString("ActionYouScoredInGame", mpEIGo.juqQQs.esbSDO.R.string.ActionYouScoredInGame, LocaleController.formatPluralString("Points", this.messageOwner.action.score));
        }
        this.messageText = replaceWithLink(this.messageText, "un2", game);
    }

    public boolean hasValidReplyMessageObject() {
        MessageObject messageObject = this.replyMessageObject;
        if (messageObject != null) {
            TLRPC.Message message = messageObject.messageOwner;
            if (!(message instanceof TLRPC.TL_messageEmpty) && !(message.action instanceof TLRPC.TL_messageActionHistoryClear)) {
                return true;
            }
        }
        return false;
    }

    public void generatePaymentSentMessageText(TLRPC.User fromUser) {
        String name;
        if (fromUser == null) {
            fromUser = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf((int) getDialogId()));
        }
        if (fromUser != null) {
            name = UserObject.getFirstName(fromUser);
        } else {
            name = "";
        }
        MessageObject messageObject = this.replyMessageObject;
        if (messageObject != null && (messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaInvoice)) {
            this.messageText = LocaleController.formatString("PaymentSuccessfullyPaid", mpEIGo.juqQQs.esbSDO.R.string.PaymentSuccessfullyPaid, LocaleController.getInstance().formatCurrencyString(this.messageOwner.action.total_amount, this.messageOwner.action.currency), name, this.replyMessageObject.messageOwner.media.title);
        } else {
            this.messageText = LocaleController.formatString("PaymentSuccessfullyPaidNoItem", mpEIGo.juqQQs.esbSDO.R.string.PaymentSuccessfullyPaidNoItem, LocaleController.getInstance().formatCurrencyString(this.messageOwner.action.total_amount, this.messageOwner.action.currency), name);
        }
    }

    public void generatePinMessageText(TLRPC.User fromUser, TLRPC.Chat chat) {
        if (fromUser == null && chat == null) {
            if (this.messageOwner.from_id > 0) {
                fromUser = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.messageOwner.from_id));
            }
            if (fromUser == null) {
                chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.messageOwner.to_id.channel_id));
            }
        }
        MessageObject messageObject = this.replyMessageObject;
        if (messageObject != null) {
            TLRPC.Message message = messageObject.messageOwner;
            if (!(message instanceof TLRPC.TL_messageEmpty) && !(message.action instanceof TLRPC.TL_messageActionHistoryClear)) {
                if (!this.replyMessageObject.isMusic()) {
                    if (!this.replyMessageObject.isVideo()) {
                        if (!this.replyMessageObject.isGif()) {
                            if (!this.replyMessageObject.isVoice()) {
                                if (!this.replyMessageObject.isRoundVideo()) {
                                    if (!this.replyMessageObject.isSticker() && !this.replyMessageObject.isAnimatedSticker()) {
                                        if (!(this.replyMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaDocument)) {
                                            if (!(this.replyMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaGeo)) {
                                                if (!(this.replyMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaGeoLive)) {
                                                    if (!(this.replyMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaContact)) {
                                                        if (!(this.replyMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaPoll)) {
                                                            if (!(this.replyMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto)) {
                                                                if (this.replyMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaGame) {
                                                                    CharSequence charSequenceReplaceWithLink = replaceWithLink(LocaleController.formatString("ActionPinnedGame", mpEIGo.juqQQs.esbSDO.R.string.ActionPinnedGame, "🎮 " + this.replyMessageObject.messageOwner.media.game.title), "un1", fromUser != null ? fromUser : chat);
                                                                    this.messageText = charSequenceReplaceWithLink;
                                                                    this.messageText = Emoji.replaceEmoji(charSequenceReplaceWithLink, Theme.chat_msgTextPaint.getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
                                                                    return;
                                                                }
                                                                CharSequence charSequence = this.replyMessageObject.messageText;
                                                                if (charSequence != null && charSequence.length() > 0) {
                                                                    CharSequence mess = this.replyMessageObject.messageText;
                                                                    if (mess.length() > 20) {
                                                                        mess = ((Object) mess.subSequence(0, 20)) + "...";
                                                                    }
                                                                    this.messageText = replaceWithLink(LocaleController.formatString("ActionPinnedText", mpEIGo.juqQQs.esbSDO.R.string.ActionPinnedText, Emoji.replaceEmoji(mess, Theme.chat_msgTextPaint.getFontMetricsInt(), AndroidUtilities.dp(20.0f), false)), "un1", fromUser != null ? fromUser : chat);
                                                                    return;
                                                                }
                                                                this.messageText = replaceWithLink(LocaleController.getString("ActionPinnedNoText", mpEIGo.juqQQs.esbSDO.R.string.ActionPinnedNoText), "un1", fromUser != null ? fromUser : chat);
                                                                return;
                                                            }
                                                            this.messageText = replaceWithLink(LocaleController.getString("ActionPinnedPhoto", mpEIGo.juqQQs.esbSDO.R.string.ActionPinnedPhoto), "un1", fromUser != null ? fromUser : chat);
                                                            return;
                                                        }
                                                        this.messageText = replaceWithLink(LocaleController.getString("ActionPinnedPoll", mpEIGo.juqQQs.esbSDO.R.string.ActionPinnedPoll), "un1", fromUser != null ? fromUser : chat);
                                                        return;
                                                    }
                                                    this.messageText = replaceWithLink(LocaleController.getString("ActionPinnedContact", mpEIGo.juqQQs.esbSDO.R.string.ActionPinnedContact), "un1", fromUser != null ? fromUser : chat);
                                                    return;
                                                }
                                                this.messageText = replaceWithLink(LocaleController.getString("ActionPinnedGeoLive", mpEIGo.juqQQs.esbSDO.R.string.ActionPinnedGeoLive), "un1", fromUser != null ? fromUser : chat);
                                                return;
                                            }
                                            this.messageText = replaceWithLink(LocaleController.getString("ActionPinnedGeo", mpEIGo.juqQQs.esbSDO.R.string.ActionPinnedGeo), "un1", fromUser != null ? fromUser : chat);
                                            return;
                                        }
                                        this.messageText = replaceWithLink(LocaleController.getString("ActionPinnedFile", mpEIGo.juqQQs.esbSDO.R.string.ActionPinnedFile), "un1", fromUser != null ? fromUser : chat);
                                        return;
                                    }
                                    this.messageText = replaceWithLink(LocaleController.getString("ActionPinnedSticker", mpEIGo.juqQQs.esbSDO.R.string.ActionPinnedSticker), "un1", fromUser != null ? fromUser : chat);
                                    return;
                                }
                                this.messageText = replaceWithLink(LocaleController.getString("ActionPinnedRound", mpEIGo.juqQQs.esbSDO.R.string.ActionPinnedRound), "un1", fromUser != null ? fromUser : chat);
                                return;
                            }
                            this.messageText = replaceWithLink(LocaleController.getString("ActionPinnedVoice", mpEIGo.juqQQs.esbSDO.R.string.ActionPinnedVoice), "un1", fromUser != null ? fromUser : chat);
                            return;
                        }
                        this.messageText = replaceWithLink(LocaleController.getString("ActionPinnedGif", mpEIGo.juqQQs.esbSDO.R.string.ActionPinnedGif), "un1", fromUser != null ? fromUser : chat);
                        return;
                    }
                    this.messageText = replaceWithLink(LocaleController.getString("ActionPinnedVideo", mpEIGo.juqQQs.esbSDO.R.string.ActionPinnedVideo), "un1", fromUser != null ? fromUser : chat);
                    return;
                }
                this.messageText = replaceWithLink(LocaleController.getString("ActionPinnedMusic", mpEIGo.juqQQs.esbSDO.R.string.ActionPinnedMusic), "un1", fromUser != null ? fromUser : chat);
                return;
            }
        }
        this.messageText = replaceWithLink(LocaleController.getString("ActionPinnedNoText", mpEIGo.juqQQs.esbSDO.R.string.ActionPinnedNoText), "un1", fromUser != null ? fromUser : chat);
    }

    public static void updateReactions(TLRPC.Message message, TLRPC.TL_messageReactions reactions) {
        if (message == null || reactions == null) {
            return;
        }
        if (reactions.min && message.reactions != null) {
            int a = 0;
            int N = message.reactions.results.size();
            while (true) {
                if (a >= N) {
                    break;
                }
                TLRPC.TL_reactionCount reaction = message.reactions.results.get(a);
                if (!reaction.chosen) {
                    a++;
                } else {
                    int b = 0;
                    int N2 = reactions.results.size();
                    while (true) {
                        if (b >= N2) {
                            break;
                        }
                        TLRPC.TL_reactionCount newReaction = reactions.results.get(b);
                        if (!reaction.reaction.equals(newReaction.reaction)) {
                            b++;
                        } else {
                            newReaction.chosen = true;
                            break;
                        }
                    }
                }
            }
        }
        message.reactions = reactions;
        message.flags |= 1048576;
    }

    public boolean hasReactions() {
        return (this.messageOwner.reactions == null || this.messageOwner.reactions.results.isEmpty()) ? false : true;
    }

    public static void updatePollResults(TLRPC.TL_messageMediaPoll media, TLRPC.TL_pollResults results) {
        if ((results.flags & 2) != 0) {
            byte[] chosen = null;
            if (results.min && media.results.results != null) {
                int b = 0;
                int N2 = media.results.results.size();
                while (true) {
                    if (b >= N2) {
                        break;
                    }
                    TLRPC.TL_pollAnswerVoters answerVoters = media.results.results.get(b);
                    if (!answerVoters.chosen) {
                        b++;
                    } else {
                        chosen = answerVoters.option;
                        break;
                    }
                }
            }
            media.results.results = results.results;
            if (chosen != null) {
                int b2 = 0;
                int N22 = media.results.results.size();
                while (true) {
                    if (b2 >= N22) {
                        break;
                    }
                    TLRPC.TL_pollAnswerVoters answerVoters2 = media.results.results.get(b2);
                    if (!Arrays.equals(answerVoters2.option, chosen)) {
                        b2++;
                    } else {
                        answerVoters2.chosen = true;
                        break;
                    }
                }
            }
            media.results.flags |= 2;
        }
        if ((results.flags & 4) != 0) {
            media.results.total_voters = results.total_voters;
            media.results.flags |= 4;
        }
    }

    public boolean isPollClosed() {
        if (this.type != 17) {
            return false;
        }
        return ((TLRPC.TL_messageMediaPoll) this.messageOwner.media).poll.closed;
    }

    public boolean isVoted() {
        if (this.type != 17) {
            return false;
        }
        TLRPC.TL_messageMediaPoll mediaPoll = (TLRPC.TL_messageMediaPoll) this.messageOwner.media;
        if (mediaPoll.results == null || mediaPoll.results.results.isEmpty()) {
            return false;
        }
        int N = mediaPoll.results.results.size();
        for (int a = 0; a < N; a++) {
            TLRPC.TL_pollAnswerVoters answer = mediaPoll.results.results.get(a);
            if (answer.chosen) {
                return true;
            }
        }
        return false;
    }

    public long getPollId() {
        if (this.type != 17) {
            return 0L;
        }
        return ((TLRPC.TL_messageMediaPoll) this.messageOwner.media).poll.id;
    }

    private TLRPC.Photo getPhotoWithId(TLRPC.WebPage webPage, long id) {
        if (webPage == null || webPage.cached_page == null) {
            return null;
        }
        if (webPage.photo != null && webPage.photo.id == id) {
            return webPage.photo;
        }
        for (int a = 0; a < webPage.cached_page.photos.size(); a++) {
            TLRPC.Photo photo = webPage.cached_page.photos.get(a);
            if (photo.id == id) {
                return photo;
            }
        }
        return null;
    }

    private TLRPC.Document getDocumentWithId(TLRPC.WebPage webPage, long id) {
        if (webPage == null || webPage.cached_page == null) {
            return null;
        }
        if (webPage.document != null && webPage.document.id == id) {
            return webPage.document;
        }
        for (int a = 0; a < webPage.cached_page.documents.size(); a++) {
            TLRPC.Document document = webPage.cached_page.documents.get(a);
            if (document.id == id) {
                return document;
            }
        }
        return null;
    }

    private MessageObject getMessageObjectForBlock(TLRPC.WebPage webPage, TLRPC.PageBlock pageBlock) {
        TLRPC.TL_message message = null;
        if (pageBlock instanceof TLRPC.TL_pageBlockPhoto) {
            TLRPC.TL_pageBlockPhoto pageBlockPhoto = (TLRPC.TL_pageBlockPhoto) pageBlock;
            TLRPC.Photo photo = getPhotoWithId(webPage, pageBlockPhoto.photo_id);
            if (photo == webPage.photo) {
                return this;
            }
            message = new TLRPC.TL_message();
            message.media = new TLRPC.TL_messageMediaPhoto();
            message.media.photo = photo;
        } else if (pageBlock instanceof TLRPC.TL_pageBlockVideo) {
            TLRPC.TL_pageBlockVideo pageBlockVideo = (TLRPC.TL_pageBlockVideo) pageBlock;
            TLRPC.Document document = getDocumentWithId(webPage, pageBlockVideo.video_id);
            if (document == webPage.document) {
                return this;
            }
            message = new TLRPC.TL_message();
            message.media = new TLRPC.TL_messageMediaDocument();
            message.media.document = getDocumentWithId(webPage, pageBlockVideo.video_id);
        }
        message.message = "";
        message.realId = getId();
        message.id = Utilities.random.nextInt();
        message.date = this.messageOwner.date;
        message.to_id = this.messageOwner.to_id;
        message.out = this.messageOwner.out;
        message.from_id = this.messageOwner.from_id;
        return new MessageObject(this.currentAccount, message, false);
    }

    public ArrayList<MessageObject> getWebPagePhotos(ArrayList<MessageObject> array, ArrayList<TLRPC.PageBlock> blocksToSearch) {
        ArrayList<MessageObject> messageObjects = array == null ? new ArrayList<>() : array;
        if (this.messageOwner.media == null || this.messageOwner.media.webpage == null) {
            return messageObjects;
        }
        TLRPC.WebPage webPage = this.messageOwner.media.webpage;
        if (webPage.cached_page == null) {
            return messageObjects;
        }
        ArrayList<TLRPC.PageBlock> blocks = blocksToSearch == null ? webPage.cached_page.blocks : blocksToSearch;
        for (int a = 0; a < blocks.size(); a++) {
            TLRPC.PageBlock block = blocks.get(a);
            if (block instanceof TLRPC.TL_pageBlockSlideshow) {
                TLRPC.TL_pageBlockSlideshow slideshow = (TLRPC.TL_pageBlockSlideshow) block;
                for (int b = 0; b < slideshow.items.size(); b++) {
                    messageObjects.add(getMessageObjectForBlock(webPage, slideshow.items.get(b)));
                }
            } else if (block instanceof TLRPC.TL_pageBlockCollage) {
                TLRPC.TL_pageBlockCollage slideshow2 = (TLRPC.TL_pageBlockCollage) block;
                for (int b2 = 0; b2 < slideshow2.items.size(); b2++) {
                    messageObjects.add(getMessageObjectForBlock(webPage, slideshow2.items.get(b2)));
                }
            }
        }
        return messageObjects;
    }

    public void createMessageSendInfo() {
        String param;
        if (this.messageOwner.message != null) {
            if ((this.messageOwner.id < 0 || isEditing()) && this.messageOwner.params != null) {
                String param2 = this.messageOwner.params.get("ve");
                if (param2 != null && (isVideo() || isNewGif() || isRoundVideo())) {
                    VideoEditedInfo videoEditedInfo = new VideoEditedInfo();
                    this.videoEditedInfo = videoEditedInfo;
                    if (!videoEditedInfo.parseString(param2)) {
                        this.videoEditedInfo = null;
                    } else {
                        this.videoEditedInfo.roundVideo = isRoundVideo();
                    }
                }
                if (this.messageOwner.send_state == 3 && (param = this.messageOwner.params.get("prevMedia")) != null) {
                    SerializedData serializedData = new SerializedData(Base64.decode(param, 0));
                    int constructor = serializedData.readInt32(false);
                    this.previousMedia = TLRPC.MessageMedia.TLdeserialize(serializedData, constructor, false);
                    this.previousCaption = serializedData.readString(false);
                    this.previousAttachPath = serializedData.readString(false);
                    int count = serializedData.readInt32(false);
                    this.previousCaptionEntities = new ArrayList<>(count);
                    for (int a = 0; a < count; a++) {
                        int constructor2 = serializedData.readInt32(false);
                        TLRPC.MessageEntity entity = TLRPC.MessageEntity.TLdeserialize(serializedData, constructor2, false);
                        this.previousCaptionEntities.add(entity);
                    }
                    serializedData.cleanup();
                }
            }
        }
    }

    public void measureInlineBotButtons() {
        CharSequence text;
        this.wantedBotKeyboardWidth = 0;
        if ((this.messageOwner.reply_markup instanceof TLRPC.TL_replyInlineMarkup) || (this.messageOwner.reactions != null && !this.messageOwner.reactions.results.isEmpty())) {
            Theme.createChatResources(null, true);
            StringBuilder sb = this.botButtonsLayout;
            if (sb == null) {
                this.botButtonsLayout = new StringBuilder();
            } else {
                sb.setLength(0);
            }
        }
        float f = 2000.0f;
        float f2 = 15.0f;
        if (this.messageOwner.reply_markup instanceof TLRPC.TL_replyInlineMarkup) {
            int a = 0;
            while (a < this.messageOwner.reply_markup.rows.size()) {
                TLRPC.TL_keyboardButtonRow row = this.messageOwner.reply_markup.rows.get(a);
                int maxButtonSize = 0;
                int size = row.buttons.size();
                int b = 0;
                while (b < size) {
                    TLRPC.KeyboardButton button = row.buttons.get(b);
                    StringBuilder sb2 = this.botButtonsLayout;
                    sb2.append(a);
                    sb2.append(b);
                    if ((button instanceof TLRPC.TL_keyboardButtonBuy) && (this.messageOwner.media.flags & 4) != 0) {
                        text = LocaleController.getString("PaymentReceipt", mpEIGo.juqQQs.esbSDO.R.string.PaymentReceipt);
                    } else {
                        CharSequence text2 = button.text;
                        text = Emoji.replaceEmoji(text2, Theme.chat_msgBotButtonPaint.getFontMetricsInt(), AndroidUtilities.dp(f2), false);
                    }
                    StaticLayout staticLayout = new StaticLayout(text, Theme.chat_msgBotButtonPaint, AndroidUtilities.dp(f), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                    if (staticLayout.getLineCount() > 0) {
                        float width = staticLayout.getLineWidth(0);
                        float left = staticLayout.getLineLeft(0);
                        if (left < width) {
                            width -= left;
                        }
                        maxButtonSize = Math.max(maxButtonSize, ((int) Math.ceil(width)) + AndroidUtilities.dp(4.0f));
                    }
                    b++;
                    f = 2000.0f;
                    f2 = 15.0f;
                }
                this.wantedBotKeyboardWidth = Math.max(this.wantedBotKeyboardWidth, ((AndroidUtilities.dp(12.0f) + maxButtonSize) * size) + (AndroidUtilities.dp(5.0f) * (size - 1)));
                a++;
                f = 2000.0f;
                f2 = 15.0f;
            }
            return;
        }
        if (this.messageOwner.reactions != null) {
            int size2 = this.messageOwner.reactions.results.size();
            for (int a2 = 0; a2 < size2; a2++) {
                TLRPC.TL_reactionCount reactionCount = this.messageOwner.reactions.results.get(a2);
                int maxButtonSize2 = 0;
                StringBuilder sb3 = this.botButtonsLayout;
                sb3.append(0);
                sb3.append(a2);
                CharSequence text3 = Emoji.replaceEmoji(String.format("%d %s", Integer.valueOf(reactionCount.count), reactionCount.reaction), Theme.chat_msgBotButtonPaint.getFontMetricsInt(), AndroidUtilities.dp(15.0f), false);
                StaticLayout staticLayout2 = new StaticLayout(text3, Theme.chat_msgBotButtonPaint, AndroidUtilities.dp(2000.0f), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                if (staticLayout2.getLineCount() > 0) {
                    float width2 = staticLayout2.getLineWidth(0);
                    float left2 = staticLayout2.getLineLeft(0);
                    if (left2 < width2) {
                        width2 -= left2;
                    }
                    maxButtonSize2 = Math.max(0, ((int) Math.ceil(width2)) + AndroidUtilities.dp(4.0f));
                }
                this.wantedBotKeyboardWidth = Math.max(this.wantedBotKeyboardWidth, ((AndroidUtilities.dp(12.0f) + maxButtonSize2) * size2) + (AndroidUtilities.dp(5.0f) * (size2 - 1)));
            }
        }
    }

    public boolean isFcmMessage() {
        return this.localType != 0;
    }

    public void setDelegate(Delegate delegate) {
        this.delegate = delegate;
    }

    public String setMoneyFormat(String data) {
        if (NumberUtil.isNumber(data)) {
            if (data.contains(".")) {
                String[] split = data.split("\\.");
                String number1 = split[0];
                String number2 = split[1];
                String res = MoneyUtil.formatToString(new BigDecimal(String.valueOf(number1)).multiply(new BigDecimal("1")).toString(), 0);
                if (number2.length() > 8) {
                    number2 = number2.substring(0, 8);
                }
                return res + "." + number2;
            }
            String res2 = MoneyUtil.formatToString(new BigDecimal(String.valueOf(data)).multiply(new BigDecimal("1")).toString(), 0);
            return res2;
        }
        return "";
    }

    /* JADX WARN: Removed duplicated region for block: B:508:0x0ed0  */
    /* JADX WARN: Removed duplicated region for block: B:510:0x0ed3  */
    /* JADX WARN: Removed duplicated region for block: B:518:0x0f1a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void updateMessageText(java.util.AbstractMap<java.lang.Integer, im.uwrkaxlmjj.tgnet.TLRPC.User> r20, java.util.AbstractMap<java.lang.Integer, im.uwrkaxlmjj.tgnet.TLRPC.Chat> r21, android.util.SparseArray<im.uwrkaxlmjj.tgnet.TLRPC.User> r22, android.util.SparseArray<im.uwrkaxlmjj.tgnet.TLRPC.Chat> r23) {
        /*
            Method dump skipped, instruction units count: 4824
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessageObject.updateMessageText(java.util.AbstractMap, java.util.AbstractMap, android.util.SparseArray, android.util.SparseArray):void");
    }

    public void setType() {
        int oldType = this.type;
        this.isRoundVideoCached = 0;
        TLRPC.Message message = this.messageOwner;
        if ((message instanceof TLRPC.TL_message) || (message instanceof TLRPC.TL_messageForwarded_old2)) {
            if (this.isRestrictedMessage) {
                this.type = 0;
            } else if (this.emojiAnimatedSticker != null) {
                if (isSticker()) {
                    this.type = 13;
                } else {
                    this.type = 15;
                }
            } else if (isMediaEmpty()) {
                this.type = 0;
                if (TextUtils.isEmpty(this.messageText) && this.eventId == 0) {
                    this.contentType = 10;
                }
            } else if (this.messageOwner.media.ttl_seconds != 0 && ((this.messageOwner.media.photo instanceof TLRPC.TL_photoEmpty) || (getDocument() instanceof TLRPC.TL_documentEmpty))) {
                this.contentType = 1;
                this.type = 10;
            } else if (this.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto) {
                this.type = 1;
            } else if ((this.messageOwner.media instanceof TLRPC.TL_messageMediaGeo) || (this.messageOwner.media instanceof TLRPC.TL_messageMediaVenue) || (this.messageOwner.media instanceof TLRPC.TL_messageMediaGeoLive)) {
                this.type = 4;
            } else if (isRoundVideo()) {
                this.type = 5;
            } else if (isVideo()) {
                this.type = 3;
            } else if (isVoice()) {
                this.type = 2;
            } else if (isMusic()) {
                this.type = 14;
            } else if (this.messageOwner.media instanceof TLRPC.TL_messageMediaContact) {
                this.type = 12;
            } else if (this.messageOwner.media instanceof TLRPC.TL_messageMediaPoll) {
                this.type = 17;
            } else if (this.messageOwner.media instanceof TLRPC.TL_messageMediaUnsupported) {
                this.type = 0;
            } else if (this.messageOwner.media instanceof TLRPC.TL_messageMediaDocument) {
                TLRPC.Document document = getDocument();
                if (document != null && document.mime_type != null) {
                    if (isGifDocument(document)) {
                        this.type = 8;
                    } else if (isSticker()) {
                        this.type = 13;
                    } else if (isAnimatedSticker()) {
                        this.type = 15;
                    } else {
                        this.type = 9;
                    }
                } else {
                    this.type = 9;
                }
            } else if ((this.messageOwner.media instanceof TLRPC.TL_messageMediaGame) || (this.messageOwner.media instanceof TLRPC.TL_messageMediaInvoice)) {
                this.type = 0;
            } else if (this.messageOwner.media instanceof TLRPCRedpacket.CL_messagesRpkTransferMedia) {
                TLRPCRedpacket.CL_messagesRpkTransferMedia media = (TLRPCRedpacket.CL_messagesRpkTransferMedia) this.messageOwner.media;
                if (media.trans == 0) {
                    this.type = 101;
                } else if (media.trans == 1 || media.trans == 2) {
                    this.type = 102;
                }
            } else if (this.messageOwner.media instanceof TLRPC.TL_messageMediaShareContact) {
                this.type = 103;
            } else if (this.messageOwner.media instanceof TLRPC.TL_messageMediaShare) {
                this.type = TYPE_LIVE;
            } else if (this.messageOwner.media instanceof TLRPCRedpacket.CL_messagesPayBillOverMedia) {
                this.contentType = 5;
                this.type = 104;
            } else if (this.messageOwner.media instanceof TLRPCContacts.TL_messageMediaSysNotify) {
                this.type = 105;
            }
        } else if (message instanceof TLRPC.TL_messageService) {
            if (message.action instanceof TLRPC.TL_messageActionLoginUnknownLocation) {
                this.type = 0;
            } else if ((this.messageOwner.action instanceof TLRPC.TL_messageActionChatEditPhoto) || (this.messageOwner.action instanceof TLRPC.TL_messageActionUserUpdatedPhoto)) {
                this.contentType = 1;
                this.type = 11;
            } else if (this.messageOwner.action instanceof TLRPC.TL_messageEncryptedAction) {
                if ((this.messageOwner.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionScreenshotMessages) || (this.messageOwner.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionSetMessageTTL)) {
                    this.contentType = 1;
                    this.type = 10;
                } else {
                    this.contentType = -1;
                    this.type = -1;
                }
            } else if (this.messageOwner.action instanceof TLRPC.TL_messageActionHistoryClear) {
                this.contentType = -1;
                this.type = -1;
            } else if (this.messageOwner.action instanceof TLRPC.TL_messageActionPhoneCall) {
                this.type = 16;
            } else {
                this.contentType = 1;
                this.type = 10;
            }
        }
        if (oldType != 1000 && oldType != this.type) {
            updateMessageText(MessagesController.getInstance(this.currentAccount).getUsers(), MessagesController.getInstance(this.currentAccount).getChats(), null, null);
            if (isMediaEmpty()) {
                this.messageText = updateMetionText(this.messageText, this.messageOwner.entities);
            }
            generateThumbs(false);
        }
    }

    public boolean checkLayout() {
        CharSequence charSequence;
        TextPaint paint;
        if (this.type != 0 || this.messageOwner.to_id == null || (charSequence = this.messageText) == null || charSequence.length() == 0) {
            return false;
        }
        if (this.layoutCreated) {
            int newMinSize = AndroidUtilities.isTablet() ? AndroidUtilities.getMinTabletSide() : AndroidUtilities.displaySize.x;
            if (Math.abs(this.generatedWithMinSize - newMinSize) > AndroidUtilities.dp(52.0f) || this.generatedWithDensity != AndroidUtilities.density) {
                this.layoutCreated = false;
            }
        }
        if (this.layoutCreated) {
            return false;
        }
        this.layoutCreated = true;
        TLRPC.User fromUser = null;
        if (isFromUser()) {
            fromUser = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.messageOwner.from_id));
        }
        if (this.messageOwner.media instanceof TLRPC.TL_messageMediaGame) {
            paint = Theme.chat_msgGameTextPaint;
        } else {
            paint = Theme.chat_msgTextPaint;
        }
        int[] emojiOnly = SharedConfig.allowBigEmoji ? new int[1] : null;
        this.messageText = Emoji.replaceEmoji(this.messageText, paint.getFontMetricsInt(), AndroidUtilities.dp(20.0f), false, emojiOnly);
        checkEmojiOnly(emojiOnly);
        generateLayout(fromUser);
        return true;
    }

    public void resetLayout() {
        this.layoutCreated = false;
    }

    public String getMimeType() {
        TLRPC.Document document = getDocument();
        if (document != null) {
            return document.mime_type;
        }
        if (!(this.messageOwner.media instanceof TLRPC.TL_messageMediaInvoice)) {
            return this.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto ? "image/jpeg" : (!(this.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) || this.messageOwner.media.webpage.photo == null) ? "" : "image/jpeg";
        }
        TLRPC.WebDocument photo = ((TLRPC.TL_messageMediaInvoice) this.messageOwner.media).photo;
        if (photo != null) {
            return photo.mime_type;
        }
        return "";
    }

    public boolean canPreviewDocument() {
        return canPreviewDocument(getDocument());
    }

    public static boolean isGifDocument(WebFile document) {
        return document != null && (document.mime_type.equals("image/gif") || isNewGifDocument(document));
    }

    public static boolean isGifDocument(TLRPC.Document document) {
        return (document == null || document.mime_type == null || (!document.mime_type.equals("image/gif") && !isNewGifDocument(document))) ? false : true;
    }

    public static boolean isDocumentHasThumb(TLRPC.Document document) {
        if (document == null || document.thumbs.isEmpty()) {
            return false;
        }
        int N = document.thumbs.size();
        for (int a = 0; a < N; a++) {
            TLRPC.PhotoSize photoSize = document.thumbs.get(a);
            if (photoSize != null && !(photoSize instanceof TLRPC.TL_photoSizeEmpty) && !(photoSize.location instanceof TLRPC.TL_fileLocationUnavailable)) {
                return true;
            }
        }
        return false;
    }

    public static boolean canPreviewDocument(TLRPC.Document document) {
        if (document != null && document.mime_type != null) {
            String mime = document.mime_type.toLowerCase();
            if (isDocumentHasThumb(document) && (mime.equals("image/png") || mime.equals("image/jpg") || mime.equals("image/jpeg"))) {
                for (int a = 0; a < document.attributes.size(); a++) {
                    TLRPC.DocumentAttribute attribute = document.attributes.get(a);
                    if (attribute instanceof TLRPC.TL_documentAttributeImageSize) {
                        TLRPC.TL_documentAttributeImageSize size = (TLRPC.TL_documentAttributeImageSize) attribute;
                        return size.w < 6000 && size.h < 6000;
                    }
                }
            } else if (BuildVars.DEBUG_PRIVATE_VERSION) {
                String fileName = FileLoader.getDocumentFileName(document);
                if (fileName.startsWith("tg_secret_sticker") && fileName.endsWith("json")) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean isRoundVideoDocument(TLRPC.Document document) {
        if (document != null && MimeTypes.VIDEO_MP4.equals(document.mime_type)) {
            int width = 0;
            int height = 0;
            boolean round = false;
            for (int a = 0; a < document.attributes.size(); a++) {
                TLRPC.DocumentAttribute attribute = document.attributes.get(a);
                if (attribute instanceof TLRPC.TL_documentAttributeVideo) {
                    width = attribute.w;
                    height = attribute.w;
                    round = attribute.round_message;
                }
            }
            if (round && width <= 1280 && height <= 1280) {
                return true;
            }
            return false;
        }
        return false;
    }

    public static boolean isNewGifDocument(WebFile document) {
        if (document != null && MimeTypes.VIDEO_MP4.equals(document.mime_type)) {
            int width = 0;
            int height = 0;
            for (int a = 0; a < document.attributes.size(); a++) {
                TLRPC.DocumentAttribute attribute = document.attributes.get(a);
                if (!(attribute instanceof TLRPC.TL_documentAttributeAnimated) && (attribute instanceof TLRPC.TL_documentAttributeVideo)) {
                    width = attribute.w;
                    height = attribute.w;
                }
            }
            if (width <= 1280 && height <= 1280) {
                return true;
            }
            return false;
        }
        return false;
    }

    public static boolean isNewGifDocument(TLRPC.Document document) {
        if (document != null && MimeTypes.VIDEO_MP4.equals(document.mime_type)) {
            int width = 0;
            int height = 0;
            boolean animated = false;
            for (int a = 0; a < document.attributes.size(); a++) {
                TLRPC.DocumentAttribute attribute = document.attributes.get(a);
                if (attribute instanceof TLRPC.TL_documentAttributeAnimated) {
                    animated = true;
                } else if (attribute instanceof TLRPC.TL_documentAttributeVideo) {
                    width = attribute.w;
                    height = attribute.w;
                }
            }
            if (animated && width <= 1280 && height <= 1280) {
                return true;
            }
            return false;
        }
        return false;
    }

    public void generateThumbs(boolean update) {
        ArrayList<TLRPC.PhotoSize> arrayList;
        ArrayList<TLRPC.PhotoSize> arrayList2;
        ArrayList<TLRPC.PhotoSize> arrayList3;
        ArrayList<TLRPC.PhotoSize> arrayList4;
        ArrayList<TLRPC.PhotoSize> arrayList5;
        ArrayList<TLRPC.PhotoSize> arrayList6;
        TLRPC.Message message = this.messageOwner;
        if (message instanceof TLRPC.TL_messageService) {
            if (message.action instanceof TLRPC.TL_messageActionChatEditPhoto) {
                TLRPC.Photo photo = this.messageOwner.action.photo;
                if (!update) {
                    this.photoThumbs = new ArrayList<>(photo.sizes);
                } else {
                    ArrayList<TLRPC.PhotoSize> arrayList7 = this.photoThumbs;
                    if (arrayList7 != null && !arrayList7.isEmpty()) {
                        for (int a = 0; a < this.photoThumbs.size(); a++) {
                            TLRPC.PhotoSize photoObject = this.photoThumbs.get(a);
                            int b = 0;
                            while (true) {
                                if (b < photo.sizes.size()) {
                                    TLRPC.PhotoSize size = photo.sizes.get(b);
                                    if ((size instanceof TLRPC.TL_photoSizeEmpty) || !size.type.equals(photoObject.type)) {
                                        b++;
                                    } else {
                                        photoObject.location = size.location;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                int a2 = photo.dc_id;
                if (a2 != 0) {
                    int N = this.photoThumbs.size();
                    for (int a3 = 0; a3 < N; a3++) {
                        TLRPC.FileLocation location = this.photoThumbs.get(a3).location;
                        location.dc_id = photo.dc_id;
                        location.file_reference = photo.file_reference;
                    }
                }
                this.photoThumbsObject = this.messageOwner.action.photo;
                return;
            }
            return;
        }
        if (this.emojiAnimatedSticker != null) {
            if (TextUtils.isEmpty(this.emojiAnimatedStickerColor) && isDocumentHasThumb(this.emojiAnimatedSticker)) {
                if (!update || (arrayList6 = this.photoThumbs) == null) {
                    ArrayList<TLRPC.PhotoSize> arrayList8 = new ArrayList<>();
                    this.photoThumbs = arrayList8;
                    arrayList8.addAll(this.emojiAnimatedSticker.thumbs);
                } else if (arrayList6 != null && !arrayList6.isEmpty()) {
                    updatePhotoSizeLocations(this.photoThumbs, this.emojiAnimatedSticker.thumbs);
                }
                this.photoThumbsObject = this.emojiAnimatedSticker;
                return;
            }
            return;
        }
        if (message.media != null && !(this.messageOwner.media instanceof TLRPC.TL_messageMediaEmpty)) {
            if (this.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto) {
                TLRPC.Photo photo2 = this.messageOwner.media.photo;
                if (!update || ((arrayList5 = this.photoThumbs) != null && arrayList5.size() != photo2.sizes.size())) {
                    this.photoThumbs = new ArrayList<>(photo2.sizes);
                } else {
                    ArrayList<TLRPC.PhotoSize> arrayList9 = this.photoThumbs;
                    if (arrayList9 != null && !arrayList9.isEmpty()) {
                        for (int a4 = 0; a4 < this.photoThumbs.size(); a4++) {
                            TLRPC.PhotoSize photoObject2 = this.photoThumbs.get(a4);
                            if (photoObject2 != null) {
                                int b2 = 0;
                                while (true) {
                                    if (b2 >= photo2.sizes.size()) {
                                        break;
                                    }
                                    TLRPC.PhotoSize size2 = photo2.sizes.get(b2);
                                    if (size2 == null || (size2 instanceof TLRPC.TL_photoSizeEmpty) || !size2.type.equals(photoObject2.type)) {
                                        b2++;
                                    } else {
                                        photoObject2.location = size2.location;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                this.photoThumbsObject = this.messageOwner.media.photo;
                return;
            }
            if (this.messageOwner.media instanceof TLRPC.TL_messageMediaDocument) {
                TLRPC.Document document = getDocument();
                if (isDocumentHasThumb(document)) {
                    if (!update || (arrayList4 = this.photoThumbs) == null) {
                        ArrayList<TLRPC.PhotoSize> arrayList10 = new ArrayList<>();
                        this.photoThumbs = arrayList10;
                        arrayList10.addAll(document.thumbs);
                    } else if (arrayList4 != null && !arrayList4.isEmpty()) {
                        updatePhotoSizeLocations(this.photoThumbs, document.thumbs);
                    }
                    this.photoThumbsObject = document;
                    return;
                }
                return;
            }
            if (this.messageOwner.media instanceof TLRPC.TL_messageMediaGame) {
                TLRPC.Document document2 = this.messageOwner.media.game.document;
                if (document2 != null && isDocumentHasThumb(document2)) {
                    if (!update) {
                        ArrayList<TLRPC.PhotoSize> arrayList11 = new ArrayList<>();
                        this.photoThumbs = arrayList11;
                        arrayList11.addAll(document2.thumbs);
                    } else {
                        ArrayList<TLRPC.PhotoSize> arrayList12 = this.photoThumbs;
                        if (arrayList12 != null && !arrayList12.isEmpty()) {
                            updatePhotoSizeLocations(this.photoThumbs, document2.thumbs);
                        }
                    }
                    this.photoThumbsObject = document2;
                }
                TLRPC.Photo photo3 = this.messageOwner.media.game.photo;
                if (photo3 != null) {
                    if (!update || (arrayList3 = this.photoThumbs2) == null) {
                        this.photoThumbs2 = new ArrayList<>(photo3.sizes);
                    } else if (!arrayList3.isEmpty()) {
                        updatePhotoSizeLocations(this.photoThumbs2, photo3.sizes);
                    }
                    this.photoThumbsObject2 = photo3;
                }
                if (this.photoThumbs == null && (arrayList2 = this.photoThumbs2) != null) {
                    this.photoThumbs = arrayList2;
                    this.photoThumbs2 = null;
                    this.photoThumbsObject = this.photoThumbsObject2;
                    this.photoThumbsObject2 = null;
                    return;
                }
                return;
            }
            if (this.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) {
                TLRPC.Photo photo4 = this.messageOwner.media.webpage.photo;
                TLRPC.Document document3 = this.messageOwner.media.webpage.document;
                if (photo4 != null) {
                    if (!update || (arrayList = this.photoThumbs) == null) {
                        this.photoThumbs = new ArrayList<>(photo4.sizes);
                    } else if (!arrayList.isEmpty()) {
                        updatePhotoSizeLocations(this.photoThumbs, photo4.sizes);
                    }
                    this.photoThumbsObject = photo4;
                    return;
                }
                if (document3 != null && isDocumentHasThumb(document3)) {
                    if (!update) {
                        ArrayList<TLRPC.PhotoSize> arrayList13 = new ArrayList<>();
                        this.photoThumbs = arrayList13;
                        arrayList13.addAll(document3.thumbs);
                    } else {
                        ArrayList<TLRPC.PhotoSize> arrayList14 = this.photoThumbs;
                        if (arrayList14 != null && !arrayList14.isEmpty()) {
                            updatePhotoSizeLocations(this.photoThumbs, document3.thumbs);
                        }
                    }
                    this.photoThumbsObject = document3;
                }
            }
        }
    }

    private static void updatePhotoSizeLocations(ArrayList<TLRPC.PhotoSize> o, ArrayList<TLRPC.PhotoSize> n) {
        int N = o.size();
        for (int a = 0; a < N; a++) {
            TLRPC.PhotoSize photoObject = o.get(a);
            int b = 0;
            int N2 = n.size();
            while (true) {
                if (b < N2) {
                    TLRPC.PhotoSize size = n.get(b);
                    if ((size instanceof TLRPC.TL_photoSizeEmpty) || (size instanceof TLRPC.TL_photoCachedSize) || !size.type.equals(photoObject.type)) {
                        b++;
                    } else {
                        photoObject.location = size.location;
                        break;
                    }
                }
            }
        }
    }

    public CharSequence replaceWithLink(CharSequence source, String param, ArrayList<Integer> uids, AbstractMap<Integer, TLRPC.User> usersDict, SparseArray<TLRPC.User> sUsersDict) {
        if (TextUtils.indexOf(source, param) >= 0) {
            SpannableStringBuilder names = new SpannableStringBuilder("");
            for (int a = 0; a < uids.size(); a++) {
                TLRPC.User user = null;
                if (usersDict != null) {
                    TLRPC.User user2 = usersDict.get(uids.get(a));
                    user = user2;
                } else if (sUsersDict != null) {
                    TLRPC.User user3 = sUsersDict.get(uids.get(a).intValue());
                    user = user3;
                }
                if (user == null) {
                    user = MessagesController.getInstance(this.currentAccount).getUser(uids.get(a));
                }
                if (user != null) {
                    String name = UserObject.getName(user);
                    int start = names.length();
                    if (names.length() != 0) {
                        names.append(", ");
                    }
                    names.append((CharSequence) name);
                    names.setSpan(new URLSpanNoUnderlineBold("" + user.id), start, name.length() + start, 33);
                }
            }
            return TextUtils.replace(source, new String[]{param}, new CharSequence[]{names});
        }
        return source;
    }

    public CharSequence replaceWithLink(CharSequence source, String param, TLObject object, int status, ClickableSpan clickableSpan) {
        String name;
        String id;
        int start = TextUtils.indexOf(source, param);
        if (start < 0) {
            return source;
        }
        if (object instanceof TLRPC.User) {
            TLRPC.User user = (TLRPC.User) object;
            if (user.id == UserConfig.getInstance(UserConfig.selectedAccount).clientUserId) {
                name = LocaleController.getString("YouSelf", mpEIGo.juqQQs.esbSDO.R.string.YouSelf);
            } else {
                name = UserObject.getName((TLRPC.User) object);
            }
            id = "" + user.id;
        } else if (object instanceof TLRPC.Chat) {
            name = ((TLRPC.Chat) object).title;
            id = "" + (-((TLRPC.Chat) object).id);
        } else if (object instanceof TLRPC.TL_game) {
            TLRPC.TL_game game = (TLRPC.TL_game) object;
            name = game.title;
            id = "game";
        } else {
            name = "";
            id = "0";
        }
        String name2 = TextUtils.ellipsize(name.replace('\n', ' '), Theme.chat_actionTextPaint, AndroidUtilities.dp(150.0f), TextUtils.TruncateAt.END).toString();
        SpannableStringBuilder builder = new SpannableStringBuilder(TextUtils.replace(source, new String[]{param}, new String[]{name2}));
        Drawable drawable = Theme.chat_redpkgSamllIcon;
        if (drawable == null) {
            Theme.chat_redpkgSamllIcon = ApplicationLoader.applicationContext.getResources().getDrawable(mpEIGo.juqQQs.esbSDO.R.id.ic_red_small).mutate();
            drawable = Theme.chat_redpkgSamllIcon;
        }
        drawable.setBounds(0, 0, AndroidUtilities.dp(16.0f), AndroidUtilities.dp(18.0f));
        ImageSpan ab = new ImageSpan(drawable);
        builder.setSpan(ab, 0, 1, 33);
        builder.setSpan(new URLSpanNoUnderlineBold("" + id), start, name2.length() + start, 33);
        ForegroundColorSpan colorSpan = new ForegroundColorSpan(Theme.getColor(Theme.key_chat_redpacketLinkServiceText));
        builder.setSpan(colorSpan, start, name2.length() + start, 33);
        if (clickableSpan != null) {
            builder.setSpan(clickableSpan, builder.length() - 2, builder.length(), 33);
            ForegroundColorSpan foregroundColorSpan = new ForegroundColorSpan(Color.parseColor("#FFFE5548"));
            builder.setSpan(foregroundColorSpan, builder.length() - 2, builder.length(), 33);
        }
        if (status == 1) {
            builder.append((CharSequence) LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.YouPacketComplete));
        }
        return builder;
    }

    public CharSequence replaceWithLink(CharSequence source, String param, TLObject object) {
        return replaceWithLink(source, param, object, false);
    }

    public CharSequence replaceWithLink(CharSequence source, String param, TLObject object, boolean forRedpacket) {
        String name;
        String id;
        if (source == null) {
            return "";
        }
        int start = TextUtils.indexOf(source, param);
        if (start >= 0) {
            if (object instanceof TLRPC.User) {
                name = UserObject.getName((TLRPC.User) object);
                id = "" + ((TLRPC.User) object).id;
            } else if (object instanceof TLRPC.Chat) {
                name = ((TLRPC.Chat) object).title;
                id = "" + (-((TLRPC.Chat) object).id);
            } else if (object instanceof TLRPC.TL_game) {
                TLRPC.TL_game game = (TLRPC.TL_game) object;
                String name2 = game.title;
                id = "game";
                name = name2;
            } else {
                name = "";
                id = "0";
            }
            String name3 = name.replace('\n', ' ');
            if (forRedpacket) {
                name3 = TextUtils.ellipsize(name3, Theme.chat_actionTextPaint, AndroidUtilities.dp(150.0f), TextUtils.TruncateAt.END).toString();
            }
            SpannableStringBuilder builder = new SpannableStringBuilder(TextUtils.replace(source, new String[]{param}, new String[]{name3}));
            builder.setSpan(new URLSpanNoUnderlineBold("" + id), start, name3.length() + start, 33);
            if (forRedpacket) {
                ForegroundColorSpan colorSpan = new ForegroundColorSpan(Theme.getColor(Theme.key_chat_redpacketLinkServiceText));
                builder.setSpan(colorSpan, start, name3.length() + start, 33);
            }
            return builder;
        }
        return source;
    }

    public CharSequence replaceRedStrWithLink(CharSequence source, String param, TLObject object, boolean forRedpacket) {
        String name;
        String id;
        if (source == null) {
            return "";
        }
        int start = TextUtils.indexOf(source, param);
        if (start >= 0) {
            if (object instanceof TLRPC.User) {
                TLRPC.User user = (TLRPC.User) object;
                if (user.id == UserConfig.getInstance(UserConfig.selectedAccount).clientUserId) {
                    name = LocaleController.getString("YouSelf", mpEIGo.juqQQs.esbSDO.R.string.YouSelf);
                } else {
                    name = UserObject.getName((TLRPC.User) object);
                }
                id = "" + user.id;
            } else if (object instanceof TLRPC.Chat) {
                name = ((TLRPC.Chat) object).title;
                id = "" + (-((TLRPC.Chat) object).id);
            } else if (object instanceof TLRPC.TL_game) {
                TLRPC.TL_game game = (TLRPC.TL_game) object;
                name = game.title;
                id = "game";
            } else {
                name = "";
                id = "0";
            }
            String name2 = name.replace('\n', ' ');
            if (forRedpacket) {
                name2 = TextUtils.ellipsize(name2, Theme.chat_actionTextPaint, AndroidUtilities.dp(150.0f), TextUtils.TruncateAt.END).toString();
            }
            SpannableStringBuilder builder = new SpannableStringBuilder(TextUtils.replace(source, new String[]{param}, new String[]{name2}));
            builder.setSpan(new URLSpanNoUnderlineBold("" + id), start, name2.length() + start, 33);
            if (forRedpacket) {
                ForegroundColorSpan colorSpan = new ForegroundColorSpan(Theme.getColor(Theme.key_chat_redpacketLinkServiceText));
                builder.setSpan(colorSpan, start, name2.length() + start, 33);
            }
            return builder;
        }
        return source;
    }

    public CharSequence replaceRedStrWithLink(CharSequence source, String param, TLObject object, int status, ClickableSpan clickableSpan) {
        int start = TextUtils.indexOf(source, param);
        if (start >= 0) {
            String name = LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.CgCoinRedpacket).replace('\n', ' ');
            SpannableStringBuilder builder = new SpannableStringBuilder(TextUtils.replace(source, new String[]{param}, new String[]{name}));
            Drawable drawable = Theme.chat_redpkgSamllIcon;
            if (drawable == null) {
                Theme.chat_redpkgSamllIcon = ApplicationLoader.applicationContext.getResources().getDrawable(mpEIGo.juqQQs.esbSDO.R.id.ic_red_small).mutate();
                drawable = Theme.chat_redpkgSamllIcon;
            }
            drawable.setBounds(0, 0, AndroidUtilities.dp(16.0f), AndroidUtilities.dp(18.0f));
            ImageSpan ab = new ImageSpan(drawable);
            builder.setSpan(ab, 0, 1, 33);
            if (clickableSpan != null) {
                builder.setSpan(clickableSpan, start, name.length() + start, 33);
                ForegroundColorSpan foregroundColorSpan = new ForegroundColorSpan(Color.parseColor("#FFFE5548"));
                builder.setSpan(foregroundColorSpan, start, name.length() + start, 33);
            }
            if (status == 1) {
                builder.append((CharSequence) LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.YouPacketComplete));
            }
            return builder;
        }
        return source;
    }

    public String getExtension() {
        String fileName = getFileName();
        int idx = fileName.lastIndexOf(46);
        String ext = null;
        if (idx != -1) {
            ext = fileName.substring(idx + 1);
        }
        if (ext == null || ext.length() == 0) {
            ext = getDocument().mime_type;
        }
        if (ext == null) {
            ext = "";
        }
        return ext.toUpperCase();
    }

    public String getFileName() {
        TLRPC.PhotoSize sizeFull;
        if (this.messageOwner.media instanceof TLRPC.TL_messageMediaDocument) {
            return FileLoader.getAttachFileName(getDocument());
        }
        if (this.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto) {
            ArrayList<TLRPC.PhotoSize> sizes = this.messageOwner.media.photo.sizes;
            if (sizes.size() > 0 && (sizeFull = FileLoader.getClosestPhotoSizeWithSize(sizes, AndroidUtilities.getPhotoSize())) != null) {
                return FileLoader.getAttachFileName(sizeFull);
            }
            return "";
        }
        if (this.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) {
            return FileLoader.getAttachFileName(this.messageOwner.media.webpage.document);
        }
        return "";
    }

    public int getFileType() {
        if (isVideo()) {
            return 2;
        }
        if (isVoice()) {
            return 1;
        }
        if (this.messageOwner.media instanceof TLRPC.TL_messageMediaDocument) {
            return 3;
        }
        if (this.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto) {
            return 0;
        }
        return 4;
    }

    private static boolean containsUrls(CharSequence message) {
        if (message == null || message.length() < 2 || message.length() > 20480) {
            return false;
        }
        int length = message.length();
        int digitsInRow = 0;
        int schemeSequence = 0;
        int dotSequence = 0;
        char lastChar = 0;
        for (int i = 0; i < length; i++) {
            char c = message.charAt(i);
            if (c >= '0' && c <= '9') {
                digitsInRow++;
                if (digitsInRow >= 6) {
                    return true;
                }
                schemeSequence = 0;
                dotSequence = 0;
            } else if (c == ' ' || digitsInRow <= 0) {
                digitsInRow = 0;
            }
            if (((c == '@' || c == '#' || c == '/' || c == '$') && i == 0) || (i != 0 && (message.charAt(i - 1) == ' ' || message.charAt(i - 1) == '\n'))) {
                return true;
            }
            if (c == ':') {
                if (schemeSequence == 0) {
                    schemeSequence = 1;
                } else {
                    schemeSequence = 0;
                }
            } else if (c == '/') {
                if (schemeSequence == 2) {
                    return true;
                }
                if (schemeSequence == 1) {
                    schemeSequence++;
                } else {
                    schemeSequence = 0;
                }
            } else if (c == '.') {
                if (dotSequence == 0 && lastChar != ' ') {
                    dotSequence++;
                } else {
                    dotSequence = 0;
                }
            } else {
                if (c != ' ' && lastChar == '.' && dotSequence == 1) {
                    return true;
                }
                dotSequence = 0;
            }
            lastChar = c;
        }
        return false;
    }

    public void generateLinkDescription() {
        if (this.linkDescription != null) {
            return;
        }
        int hashtagsType = 0;
        if ((this.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) && (this.messageOwner.media.webpage instanceof TLRPC.TL_webPage) && this.messageOwner.media.webpage.description != null) {
            this.linkDescription = Spannable.Factory.getInstance().newSpannable(this.messageOwner.media.webpage.description);
            String siteName = this.messageOwner.media.webpage.site_name;
            if (siteName != null) {
                siteName = siteName.toLowerCase();
            }
            if ("instagram".equals(siteName)) {
                hashtagsType = 1;
            } else if ("twitter".equals(siteName)) {
                hashtagsType = 2;
            }
        } else if ((this.messageOwner.media instanceof TLRPC.TL_messageMediaGame) && this.messageOwner.media.game.description != null) {
            this.linkDescription = Spannable.Factory.getInstance().newSpannable(this.messageOwner.media.game.description);
        } else if ((this.messageOwner.media instanceof TLRPC.TL_messageMediaInvoice) && this.messageOwner.media.description != null) {
            this.linkDescription = Spannable.Factory.getInstance().newSpannable(this.messageOwner.media.description);
        }
        if (!TextUtils.isEmpty(this.linkDescription)) {
            if (containsUrls(this.linkDescription)) {
                try {
                    Linkify.addLinks((Spannable) this.linkDescription, 1);
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }
            CharSequence charSequenceReplaceEmoji = Emoji.replaceEmoji(this.linkDescription, Theme.chat_msgTextPaint.getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
            this.linkDescription = charSequenceReplaceEmoji;
            if (hashtagsType != 0) {
                if (!(charSequenceReplaceEmoji instanceof Spannable)) {
                    this.linkDescription = new SpannableStringBuilder(this.linkDescription);
                }
                addUrlsByPattern(isOutOwner(), this.linkDescription, false, hashtagsType, 0);
            }
        }
    }

    public void generateCaption() {
        boolean hasEntities;
        if (this.caption == null && !isRoundVideo() && !isMediaEmpty() && !(this.messageOwner.media instanceof TLRPC.TL_messageMediaGame) && !TextUtils.isEmpty(this.messageOwner.message)) {
            CharSequence charSequenceReplaceEmoji = Emoji.replaceEmoji(this.messageOwner.message, Theme.chat_msgTextPaint.getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
            this.caption = charSequenceReplaceEmoji;
            if (charSequenceReplaceEmoji != null) {
                this.caption = updateMetionText(charSequenceReplaceEmoji, this.messageOwner.entities);
            }
            if (this.messageOwner.send_state != 0) {
                hasEntities = false;
                int a = 0;
                while (true) {
                    if (a >= this.messageOwner.entities.size()) {
                        break;
                    }
                    if (this.messageOwner.entities.get(a) instanceof TLRPC.TL_inputMessageEntityMentionName) {
                        a++;
                    } else {
                        hasEntities = true;
                        break;
                    }
                }
            } else {
                hasEntities = !this.messageOwner.entities.isEmpty();
            }
            boolean useManualParse = !hasEntities && (this.eventId != 0 || (this.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto_old) || (this.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto_layer68) || (this.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto_layer74) || (this.messageOwner.media instanceof TLRPC.TL_messageMediaDocument_old) || (this.messageOwner.media instanceof TLRPC.TL_messageMediaDocument_layer68) || (this.messageOwner.media instanceof TLRPC.TL_messageMediaDocument_layer74) || ((isOut() && this.messageOwner.send_state != 0) || this.messageOwner.id < 0));
            if (useManualParse) {
                if (containsUrls(this.caption)) {
                    try {
                        Linkify.addLinks((Spannable) this.caption, 5);
                    } catch (Exception e) {
                        FileLog.e(e);
                    }
                }
                addUrlsByPattern(isOutOwner(), this.caption, true, 0, 0);
            }
            addEntitiesToText(this.caption, useManualParse);
            if (isVideo()) {
                addUrlsByPattern(isOutOwner(), this.caption, true, 3, getDuration());
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:85:0x01fa  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x020c A[Catch: Exception -> 0x0215, TRY_LEAVE, TryCatch #1 {Exception -> 0x0215, blocks: (B:43:0x00d6, B:90:0x020c, B:44:0x00f4, B:46:0x0101, B:52:0x0117, B:53:0x0119, B:66:0x0139, B:68:0x015e, B:71:0x0185, B:73:0x01a9, B:76:0x01cf, B:79:0x01d7, B:83:0x01e6, B:84:0x01eb, B:62:0x0132, B:88:0x0201), top: B:99:0x00d6 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static void addUrlsByPattern(boolean r24, java.lang.CharSequence r25, boolean r26, int r27, int r28) {
        /*
            Method dump skipped, instruction units count: 544
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessageObject.addUrlsByPattern(boolean, java.lang.CharSequence, boolean, int, int):void");
    }

    public static int[] getWebDocumentWidthAndHeight(TLRPC.WebDocument document) {
        if (document == null) {
            return null;
        }
        int size = document.attributes.size();
        for (int a = 0; a < size; a++) {
            TLRPC.DocumentAttribute attribute = document.attributes.get(a);
            if (attribute instanceof TLRPC.TL_documentAttributeImageSize) {
                return new int[]{attribute.w, attribute.h};
            }
            if (attribute instanceof TLRPC.TL_documentAttributeVideo) {
                return new int[]{attribute.w, attribute.h};
            }
        }
        return null;
    }

    public static int getWebDocumentDuration(TLRPC.WebDocument document) {
        if (document == null) {
            return 0;
        }
        int size = document.attributes.size();
        for (int a = 0; a < size; a++) {
            TLRPC.DocumentAttribute attribute = document.attributes.get(a);
            if (attribute instanceof TLRPC.TL_documentAttributeVideo) {
                return attribute.duration;
            }
            if (attribute instanceof TLRPC.TL_documentAttributeAudio) {
                return attribute.duration;
            }
        }
        return 0;
    }

    public static int[] getInlineResultWidthAndHeight(TLRPC.BotInlineResult inlineResult) {
        int[] result = getWebDocumentWidthAndHeight(inlineResult.content);
        if (result == null) {
            int[] result2 = getWebDocumentWidthAndHeight(inlineResult.thumb);
            if (result2 == null) {
                return new int[]{0, 0};
            }
            return result2;
        }
        return result;
    }

    public static int getInlineResultDuration(TLRPC.BotInlineResult inlineResult) {
        int result = getWebDocumentDuration(inlineResult.content);
        if (result == 0) {
            return getWebDocumentDuration(inlineResult.thumb);
        }
        return result;
    }

    public boolean hasValidGroupId() {
        ArrayList<TLRPC.PhotoSize> arrayList;
        return (getGroupId() == 0 || (arrayList = this.photoThumbs) == null || arrayList.isEmpty()) ? false : true;
    }

    public long getGroupIdForUse() {
        long j = this.localSentGroupId;
        return j != 0 ? j : this.messageOwner.grouped_id;
    }

    public long getGroupId() {
        long j = this.localGroupId;
        return j != 0 ? j : getGroupIdForUse();
    }

    public static void addLinks(boolean isOut, CharSequence messageText) {
        addLinks(isOut, messageText, true);
    }

    public static void addLinks(boolean isOut, CharSequence messageText, boolean botCommands) {
        if ((messageText instanceof Spannable) && containsUrls(messageText)) {
            if (messageText.length() < 1000) {
                try {
                    Linkify.addLinks((Spannable) messageText, 5);
                } catch (Exception e) {
                    FileLog.e(e);
                }
            } else {
                try {
                    Linkify.addLinks((Spannable) messageText, 1);
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
            }
            addUrlsByPattern(isOut, messageText, botCommands, 0, 0);
        }
    }

    public void resetPlayingProgress() {
        this.audioProgress = 0.0f;
        this.audioProgressSec = 0;
        this.bufferedProgress = 0.0f;
    }

    private boolean addEntitiesToText(CharSequence text, boolean useManualParse) {
        return addEntitiesToText(text, false, useManualParse);
    }

    public boolean addEntitiesToText(CharSequence text, boolean photoViewer, boolean useManualParse) {
        if (!this.isRestrictedMessage) {
            return addEntitiesToText(text, this.entitiesCopy, isOutOwner(), this.type, true, photoViewer, useManualParse);
        }
        ArrayList<TLRPC.MessageEntity> entities = new ArrayList<>();
        TLRPC.TL_messageEntityItalic entityItalic = new TLRPC.TL_messageEntityItalic();
        entityItalic.offset = 0;
        entityItalic.length = text.length();
        entities.add(entityItalic);
        return addEntitiesToText(text, entities, isOutOwner(), this.type, true, photoViewer, useManualParse);
    }

    /* JADX WARN: Removed duplicated region for block: B:135:0x0201  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean addEntitiesToText(java.lang.CharSequence r20, java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC.MessageEntity> r21, boolean r22, int r23, boolean r24, boolean r25, boolean r26) {
        /*
            Method dump skipped, instruction units count: 1097
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessageObject.addEntitiesToText(java.lang.CharSequence, java.util.ArrayList, boolean, int, boolean, boolean, boolean):boolean");
    }

    static /* synthetic */ int lambda$addEntitiesToText$2(TLRPC.MessageEntity o1, TLRPC.MessageEntity o2) {
        if (o1.offset > o2.offset) {
            return 1;
        }
        if (o1.offset < o2.offset) {
            return -1;
        }
        return 0;
    }

    public boolean needDrawShareButton() {
        int i;
        TLRPC.Chat chat;
        if (this.scheduled || this.eventId != 0) {
            return false;
        }
        if (this.messageOwner.fwd_from != null && !isOutOwner() && this.messageOwner.fwd_from.saved_from_peer != null && getDialogId() == UserConfig.getInstance(this.currentAccount).getClientUserId()) {
            return true;
        }
        int i2 = this.type;
        if (i2 == 13 || i2 == 15) {
            return false;
        }
        if (this.messageOwner.fwd_from != null && this.messageOwner.fwd_from.channel_id != 0 && !isOutOwner()) {
            return true;
        }
        if (isFromUser()) {
            if ((this.messageOwner.media instanceof TLRPC.TL_messageMediaEmpty) || this.messageOwner.media == null || ((this.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) && !(this.messageOwner.media.webpage instanceof TLRPC.TL_webPage))) {
                return false;
            }
            TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.messageOwner.from_id));
            if (user != null && user.bot) {
                return true;
            }
            if (!isOut()) {
                if ((this.messageOwner.media instanceof TLRPC.TL_messageMediaGame) || (this.messageOwner.media instanceof TLRPC.TL_messageMediaInvoice)) {
                    return true;
                }
                return (!isMegagroup() || (chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.messageOwner.to_id.channel_id))) == null || chat.username == null || chat.username.length() <= 0 || (this.messageOwner.media instanceof TLRPC.TL_messageMediaContact) || (this.messageOwner.media instanceof TLRPC.TL_messageMediaGeo)) ? false : true;
            }
        } else if ((this.messageOwner.from_id < 0 || this.messageOwner.post) && this.messageOwner.to_id.channel_id != 0 && ((this.messageOwner.via_bot_id == 0 && this.messageOwner.reply_to_msg_id == 0) || ((i = this.type) != 13 && i != 15))) {
            return true;
        }
        return false;
    }

    public boolean isYouTubeVideo() {
        return (this.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) && this.messageOwner.media.webpage != null && !TextUtils.isEmpty(this.messageOwner.media.webpage.embed_url) && "YouTube".equals(this.messageOwner.media.webpage.site_name);
    }

    public int getMaxMessageTextWidth() {
        int maxWidth;
        int maxWidth2 = 0;
        if (AndroidUtilities.isTablet() && this.eventId != 0) {
            this.generatedWithMinSize = AndroidUtilities.dp(530.0f);
        } else {
            this.generatedWithMinSize = AndroidUtilities.isTablet() ? AndroidUtilities.getMinTabletSide() : AndroidUtilities.displaySize.x;
        }
        this.generatedWithDensity = AndroidUtilities.density;
        if ((this.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) && this.messageOwner.media.webpage != null && "app_background".equals(this.messageOwner.media.webpage.type)) {
            try {
                Uri uri = Uri.parse(this.messageOwner.media.webpage.url);
                if (uri.getQueryParameter("bg_color") != null) {
                    maxWidth2 = AndroidUtilities.dp(220.0f);
                } else if (uri.getLastPathSegment().length() == 6) {
                    maxWidth2 = AndroidUtilities.dp(200.0f);
                }
            } catch (Exception e) {
            }
        } else if (isAndroidTheme()) {
            maxWidth2 = AndroidUtilities.dp(200.0f);
        }
        if (maxWidth2 == 0) {
            int maxWidth3 = this.generatedWithMinSize - AndroidUtilities.dp(147.0f);
            if (needDrawShareButton() && !isOutOwner()) {
                maxWidth = maxWidth3 - AndroidUtilities.dp(10.0f);
            } else {
                maxWidth = maxWidth3;
            }
            if (this.messageOwner.media instanceof TLRPC.TL_messageMediaGame) {
                return maxWidth - AndroidUtilities.dp(10.0f);
            }
            return maxWidth;
        }
        return maxWidth2;
    }

    /* JADX WARN: Can't wrap try/catch for region: R(12:126|(5:252|128|129|(9:250|131|132|141|(2:248|143)|269|147|148|(3:150|254|151)(1:155))|237)(1:137)|246|138|139|140|141|(0)|269|147|148|(0)(0)) */
    /* JADX WARN: Can't wrap try/catch for region: R(21:104|(1:106)(1:107)|108|(3:110|(2:112|(2:114|(2:116|(1:119))(1:120))(1:121))|122)(5:123|(1:125)(12:126|(5:252|128|129|(9:250|131|132|141|(2:248|143)|269|147|148|(3:150|254|151)(1:155))|237)(1:137)|246|138|139|140|141|(0)|269|147|148|(0)(0))|236|281|237)|156|259|157|(1:161)|162|267|168|169|172|(1:174)|175|(1:177)|178|(6:180|(11:273|182|186|(1:188)(1:189)|275|190|191|194|(1:196)(1:197)|(1:286)(4:277|201|202|(2:204|288)(1:287))|208)|283|209|(2:211|(1:213))(2:214|(1:216))|217)(3:218|(5:220|(1:222)|223|(1:225)(1:226)|227)(1:228)|229)|230|282|237) */
    /* JADX WARN: Code restructure failed: missing block: B:163:0x03f4, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:164:0x03f5, code lost:
    
        r5 = 0.0f;
     */
    /* JADX WARN: Code restructure failed: missing block: B:165:0x03f6, code lost:
    
        if (r8 == 0) goto L166;
     */
    /* JADX WARN: Code restructure failed: missing block: B:166:0x03f8, code lost:
    
        r31.textXOffset = 0.0f;
     */
    /* JADX WARN: Code restructure failed: missing block: B:167:0x03fb, code lost:
    
        im.uwrkaxlmjj.messenger.FileLog.e(r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:170:0x0408, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:171:0x0409, code lost:
    
        r9 = 0.0f;
        im.uwrkaxlmjj.messenger.FileLog.e(r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:231:0x0547, code lost:
    
        r0 = e;
     */
    /* JADX WARN: Code restructure failed: missing block: B:232:0x0548, code lost:
    
        r18 = r3;
        r16 = r7;
        r7 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:233:0x0550, code lost:
    
        r0 = e;
     */
    /* JADX WARN: Code restructure failed: missing block: B:234:0x0551, code lost:
    
        r29 = r2;
        r26 = r6;
        r16 = r7;
        r27 = r8;
        r8 = r12;
        r18 = r13;
        r2 = r14;
        r30 = r15;
        r7 = r4;
     */
    /* JADX WARN: Removed duplicated region for block: B:150:0x03b8  */
    /* JADX WARN: Removed duplicated region for block: B:155:0x03db  */
    /* JADX WARN: Removed duplicated region for block: B:248:0x0387 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x008e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void generateLayout(im.uwrkaxlmjj.tgnet.TLRPC.User r32) {
        /*
            Method dump skipped, instruction units count: 1440
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessageObject.generateLayout(im.uwrkaxlmjj.tgnet.TLRPC$User):void");
    }

    public boolean isOut() {
        return this.messageOwner.out;
    }

    public boolean isOutOwner() {
        if (!this.messageOwner.out || this.messageOwner.from_id <= 0 || this.messageOwner.post) {
            return false;
        }
        if (this.messageOwner.fwd_from == null) {
            return true;
        }
        int selfUserId = UserConfig.getInstance(this.currentAccount).getClientUserId();
        return getDialogId() == ((long) selfUserId) ? (this.messageOwner.fwd_from.from_id == selfUserId && (this.messageOwner.fwd_from.saved_from_peer == null || this.messageOwner.fwd_from.saved_from_peer.user_id == selfUserId)) || (this.messageOwner.fwd_from.saved_from_peer != null && this.messageOwner.fwd_from.saved_from_peer.user_id == selfUserId) : this.messageOwner.fwd_from.saved_from_peer == null || this.messageOwner.fwd_from.saved_from_peer.user_id == selfUserId;
    }

    public boolean needDrawAvatar() {
        return (!isFromUser() && this.eventId == 0 && (this.messageOwner.fwd_from == null || this.messageOwner.fwd_from.saved_from_peer == null)) ? false : true;
    }

    public boolean isNewSupport() {
        TLRPC.Message message = this.messageOwner;
        return (message == null || message.media == null || !(this.messageOwner.media instanceof TLRPCContacts.TL_messageMediaSysNotify)) ? false : true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean needDrawAvatarInternal() {
        return ((!isFromChat() || !isFromUser()) && this.eventId == 0 && (this.messageOwner.fwd_from == null || this.messageOwner.fwd_from.saved_from_peer == null)) ? false : true;
    }

    public boolean isFromChat() {
        TLRPC.Chat chat;
        if (getDialogId() == UserConfig.getInstance(this.currentAccount).clientUserId || isMegagroup() || (this.messageOwner.to_id != null && this.messageOwner.to_id.chat_id != 0)) {
            return true;
        }
        return (this.messageOwner.to_id == null || this.messageOwner.to_id.channel_id == 0 || (chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.messageOwner.to_id.channel_id))) == null || !chat.megagroup) ? false : true;
    }

    public boolean isFromUser() {
        return this.messageOwner.from_id > 0 && !this.messageOwner.post;
    }

    public boolean isForwardedChannelPost() {
        return (this.messageOwner.from_id > 0 || this.messageOwner.fwd_from == null || this.messageOwner.fwd_from.channel_post == 0) ? false : true;
    }

    public boolean isUnread() {
        return this.messageOwner.unread;
    }

    public boolean isContentUnread() {
        return this.messageOwner.media_unread;
    }

    public void setIsRead() {
        this.messageOwner.unread = false;
    }

    public int getUnradFlags() {
        return getUnreadFlags(this.messageOwner);
    }

    public static int getUnreadFlags(TLRPC.Message message) {
        int flags = 0;
        if (!message.unread) {
            flags = 0 | 1;
        }
        if (!message.media_unread) {
            return flags | 2;
        }
        return flags;
    }

    public void setContentIsRead() {
        this.messageOwner.media_unread = false;
    }

    public int getId() {
        return this.messageOwner.id;
    }

    public String getTranslate() {
        return this.messageOwner.trans;
    }

    public boolean isTranslating() {
        return this.messageOwner.istransing;
    }

    public int getRealId() {
        return this.messageOwner.realId != 0 ? this.messageOwner.realId : this.messageOwner.id;
    }

    public static int getMessageSize(TLRPC.Message message) {
        TLRPC.Document document;
        if (message.media instanceof TLRPC.TL_messageMediaWebPage) {
            document = message.media.webpage.document;
        } else if (message.media instanceof TLRPC.TL_messageMediaGame) {
            document = message.media.game.document;
        } else {
            document = message.media != null ? message.media.document : null;
        }
        if (document != null) {
            return document.size;
        }
        return 0;
    }

    public int getSize() {
        return getMessageSize(this.messageOwner);
    }

    public long getIdWithChannel() {
        long id = this.messageOwner.id;
        if (this.messageOwner.to_id != null && this.messageOwner.to_id.channel_id != 0) {
            return id | (((long) this.messageOwner.to_id.channel_id) << 32);
        }
        return id;
    }

    public int getChannelId() {
        if (this.messageOwner.to_id != null) {
            return this.messageOwner.to_id.channel_id;
        }
        return 0;
    }

    public static boolean shouldEncryptPhotoOrVideo(TLRPC.Message message) {
        return message instanceof TLRPC.TL_message_secret ? ((message.media instanceof TLRPC.TL_messageMediaPhoto) || isVideoMessage(message)) && message.ttl > 0 && message.ttl <= 60 : ((message.media instanceof TLRPC.TL_messageMediaPhoto) || (message.media instanceof TLRPC.TL_messageMediaDocument)) && message.media.ttl_seconds != 0;
    }

    public boolean shouldEncryptPhotoOrVideo() {
        return shouldEncryptPhotoOrVideo(this.messageOwner);
    }

    public static boolean isSecretPhotoOrVideo(TLRPC.Message message) {
        if (message instanceof TLRPC.TL_message_secret) {
            return ((message.media instanceof TLRPC.TL_messageMediaPhoto) || isRoundVideoMessage(message) || isVideoMessage(message)) && message.ttl > 0 && message.ttl <= 60;
        }
        if (message instanceof TLRPC.TL_message) {
            return ((message.media instanceof TLRPC.TL_messageMediaPhoto) || (message.media instanceof TLRPC.TL_messageMediaDocument)) && message.media.ttl_seconds != 0;
        }
        return false;
    }

    public static boolean isSecretMedia(TLRPC.Message message) {
        if (message instanceof TLRPC.TL_message_secret) {
            return ((message.media instanceof TLRPC.TL_messageMediaPhoto) || isRoundVideoMessage(message) || isVideoMessage(message)) && message.media.ttl_seconds != 0;
        }
        if (message instanceof TLRPC.TL_message) {
            return ((message.media instanceof TLRPC.TL_messageMediaPhoto) || (message.media instanceof TLRPC.TL_messageMediaDocument)) && message.media.ttl_seconds != 0;
        }
        return false;
    }

    public boolean needDrawBluredPreview() {
        TLRPC.Message message = this.messageOwner;
        if (message instanceof TLRPC.TL_message_secret) {
            int ttl = Math.max(message.ttl, this.messageOwner.media.ttl_seconds);
            return ttl > 0 && ((((this.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto) || isVideo() || isGif()) && ttl <= 60) || isRoundVideo());
        }
        if (message instanceof TLRPC.TL_message) {
            return ((message.media instanceof TLRPC.TL_messageMediaPhoto) || (this.messageOwner.media instanceof TLRPC.TL_messageMediaDocument)) && this.messageOwner.media.ttl_seconds != 0;
        }
        return false;
    }

    public boolean isSecretMedia() {
        TLRPC.Message message = this.messageOwner;
        if (message instanceof TLRPC.TL_message_secret) {
            return (((message.media instanceof TLRPC.TL_messageMediaPhoto) || isGif()) && this.messageOwner.ttl > 0 && this.messageOwner.ttl <= 60) || isVoice() || isRoundVideo() || isVideo();
        }
        if (message instanceof TLRPC.TL_message) {
            return ((message.media instanceof TLRPC.TL_messageMediaPhoto) || (this.messageOwner.media instanceof TLRPC.TL_messageMediaDocument)) && this.messageOwner.media.ttl_seconds != 0;
        }
        return false;
    }

    public static void setUnreadFlags(TLRPC.Message message, int flag) {
        message.unread = (flag & 1) == 0;
        message.media_unread = (flag & 2) == 0;
    }

    public static boolean isUnread(TLRPC.Message message) {
        return message.unread;
    }

    public static boolean isContentUnread(TLRPC.Message message) {
        return message.media_unread;
    }

    public boolean isMegagroup() {
        return isMegagroup(this.messageOwner);
    }

    public boolean isSavedFromMegagroup() {
        if (this.messageOwner.fwd_from != null && this.messageOwner.fwd_from.saved_from_peer != null && this.messageOwner.fwd_from.saved_from_peer.channel_id != 0) {
            TLRPC.Chat chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.messageOwner.fwd_from.saved_from_peer.channel_id));
            return ChatObject.isMegagroup(chat);
        }
        return false;
    }

    public static boolean isMegagroup(TLRPC.Message message) {
        return (message.flags & Integer.MIN_VALUE) != 0;
    }

    public static boolean isOut(TLRPC.Message message) {
        return message.out;
    }

    public long getDialogId() {
        return getDialogId(this.messageOwner);
    }

    public boolean canStreamVideo() {
        TLRPC.Document document = getDocument();
        if (document == null || (document instanceof TLRPC.TL_documentEncrypted)) {
            return false;
        }
        if (SharedConfig.streamAllVideo) {
            return true;
        }
        for (int a = 0; a < document.attributes.size(); a++) {
            TLRPC.DocumentAttribute attribute = document.attributes.get(a);
            if (attribute instanceof TLRPC.TL_documentAttributeVideo) {
                return attribute.supports_streaming;
            }
            if ((attribute instanceof TLRPC.TL_documentAttributeFilename) && document.mime_type.toLowerCase().startsWith("video/")) {
                return true;
            }
        }
        return SharedConfig.streamMkv && "video/x-matroska".equals(document.mime_type);
    }

    public static long getDialogId(TLRPC.Message message) {
        if (message.dialog_id == 0 && message.to_id != null) {
            if (message.to_id.chat_id != 0) {
                message.dialog_id = -message.to_id.chat_id;
            } else if (message.to_id.channel_id != 0) {
                message.dialog_id = -message.to_id.channel_id;
            } else if (isOut(message)) {
                message.dialog_id = message.to_id.user_id;
            } else {
                message.dialog_id = message.from_id;
            }
        }
        return message.dialog_id;
    }

    public boolean isSending() {
        return this.messageOwner.send_state == 1 && this.messageOwner.id < 0;
    }

    public boolean isEditing() {
        return this.messageOwner.send_state == 3 && this.messageOwner.id > 0;
    }

    public boolean isSendError() {
        return (this.messageOwner.send_state == 2 && this.messageOwner.id < 0) || (this.scheduled && this.messageOwner.id > 0 && this.messageOwner.date < ConnectionsManager.getInstance(this.currentAccount).getCurrentTime() + (-60));
    }

    public boolean isSent() {
        return this.messageOwner.send_state == 0 || this.messageOwner.id > 0;
    }

    public int getSecretTimeLeft() {
        int secondsLeft = this.messageOwner.ttl;
        if (this.messageOwner.destroyTime != 0) {
            int secondsLeft2 = Math.max(0, this.messageOwner.destroyTime - ConnectionsManager.getInstance(this.currentAccount).getCurrentTime());
            return secondsLeft2;
        }
        return secondsLeft;
    }

    public String getSecretTimeString() {
        if (!isSecretMedia()) {
            return null;
        }
        int secondsLeft = getSecretTimeLeft();
        if (secondsLeft < 60) {
            String str = secondsLeft + "s";
            return str;
        }
        String str2 = (secondsLeft / 60) + "m";
        return str2;
    }

    public String getDocumentName() {
        return FileLoader.getDocumentFileName(getDocument());
    }

    public static boolean isStickerDocument(TLRPC.Document document) {
        if (document != null) {
            for (int a = 0; a < document.attributes.size(); a++) {
                TLRPC.DocumentAttribute attribute = document.attributes.get(a);
                if (attribute instanceof TLRPC.TL_documentAttributeSticker) {
                    return "image/webp".equals(document.mime_type) || "application/x-tgsticker".equals(document.mime_type);
                }
            }
        }
        return false;
    }

    public static boolean isAnimatedStickerDocument(TLRPC.Document document) {
        return (document == null || !"application/x-tgsticker".equals(document.mime_type) || document.thumbs.isEmpty()) ? false : true;
    }

    public static boolean canAutoplayAnimatedSticker(TLRPC.Document document) {
        return isAnimatedStickerDocument(document) && SharedConfig.getDevicePerfomanceClass() != 0;
    }

    public static boolean isMaskDocument(TLRPC.Document document) {
        if (document != null) {
            for (int a = 0; a < document.attributes.size(); a++) {
                TLRPC.DocumentAttribute attribute = document.attributes.get(a);
                if ((attribute instanceof TLRPC.TL_documentAttributeSticker) && attribute.mask) {
                    return true;
                }
            }
            return false;
        }
        return false;
    }

    public static boolean isVoiceDocument(TLRPC.Document document) {
        if (document != null) {
            for (int a = 0; a < document.attributes.size(); a++) {
                TLRPC.DocumentAttribute attribute = document.attributes.get(a);
                if (attribute instanceof TLRPC.TL_documentAttributeAudio) {
                    return attribute.voice;
                }
            }
            return false;
        }
        return false;
    }

    public static boolean isVoiceWebDocument(WebFile webDocument) {
        return webDocument != null && webDocument.mime_type.equals("audio/ogg");
    }

    public static boolean isImageWebDocument(WebFile webDocument) {
        return (webDocument == null || isGifDocument(webDocument) || !webDocument.mime_type.startsWith("image/")) ? false : true;
    }

    public static boolean isVideoWebDocument(WebFile webDocument) {
        return webDocument != null && webDocument.mime_type.startsWith("video/");
    }

    public static boolean isMusicDocument(TLRPC.Document document) {
        if (document != null) {
            for (int a = 0; a < document.attributes.size(); a++) {
                TLRPC.DocumentAttribute attribute = document.attributes.get(a);
                if (attribute instanceof TLRPC.TL_documentAttributeAudio) {
                    return true ^ attribute.voice;
                }
            }
            if (!TextUtils.isEmpty(document.mime_type)) {
                String mime = document.mime_type.toLowerCase();
                if (mime.equals(MimeTypes.AUDIO_FLAC) || mime.equals("audio/ogg") || mime.equals(MimeTypes.AUDIO_OPUS) || mime.equals("audio/x-opus+ogg")) {
                    return true;
                }
                return mime.equals("application/octet-stream") && FileLoader.getDocumentFileName(document).endsWith(".opus");
            }
            return false;
        }
        return false;
    }

    public static boolean isVideoDocument(TLRPC.Document document) {
        if (document == null) {
            return false;
        }
        boolean isAnimated = false;
        boolean isVideo = false;
        int width = 0;
        int height = 0;
        for (int a = 0; a < document.attributes.size(); a++) {
            TLRPC.DocumentAttribute attribute = document.attributes.get(a);
            if (attribute instanceof TLRPC.TL_documentAttributeVideo) {
                if (attribute.round_message) {
                    return false;
                }
                isVideo = true;
                width = attribute.w;
                height = attribute.h;
            } else if (attribute instanceof TLRPC.TL_documentAttributeAnimated) {
                isAnimated = true;
            }
        }
        if (isAnimated && (width > 1280 || height > 1280)) {
            isAnimated = false;
        }
        if (SharedConfig.streamMkv && !isVideo && "video/x-matroska".equals(document.mime_type)) {
            isVideo = true;
        }
        return isVideo && !isAnimated;
    }

    public TLRPC.Document getDocument() {
        TLRPC.Document document = this.emojiAnimatedSticker;
        if (document != null) {
            return document;
        }
        return getDocument(this.messageOwner);
    }

    public static TLRPC.Document getDocument(TLRPC.Message message) {
        if (message.media instanceof TLRPC.TL_messageMediaWebPage) {
            return message.media.webpage.document;
        }
        if (message.media instanceof TLRPC.TL_messageMediaGame) {
            return message.media.game.document;
        }
        if (message.media != null) {
            return message.media.document;
        }
        return null;
    }

    public static TLRPC.Photo getPhoto(TLRPC.Message message) {
        if (message.media instanceof TLRPC.TL_messageMediaWebPage) {
            return message.media.webpage.photo;
        }
        if (message.media != null) {
            return message.media.photo;
        }
        return null;
    }

    public static boolean isStickerMessage(TLRPC.Message message) {
        return message.media != null && isStickerDocument(message.media.document);
    }

    public static boolean isAnimatedStickerMessage(TLRPC.Message message) {
        return message.media != null && isAnimatedStickerDocument(message.media.document);
    }

    public static boolean isLocationMessage(TLRPC.Message message) {
        return (message.media instanceof TLRPC.TL_messageMediaGeo) || (message.media instanceof TLRPC.TL_messageMediaGeoLive) || (message.media instanceof TLRPC.TL_messageMediaVenue);
    }

    public static boolean isMaskMessage(TLRPC.Message message) {
        return message.media != null && isMaskDocument(message.media.document);
    }

    public static boolean isMusicMessage(TLRPC.Message message) {
        if (message.media instanceof TLRPC.TL_messageMediaWebPage) {
            return isMusicDocument(message.media.webpage.document);
        }
        return message.media != null && isMusicDocument(message.media.document);
    }

    public static boolean isGifMessage(TLRPC.Message message) {
        if (message.media instanceof TLRPC.TL_messageMediaWebPage) {
            return isGifDocument(message.media.webpage.document);
        }
        return message.media != null && isGifDocument(message.media.document);
    }

    public static boolean isRoundVideoMessage(TLRPC.Message message) {
        if (message.media instanceof TLRPC.TL_messageMediaWebPage) {
            return isRoundVideoDocument(message.media.webpage.document);
        }
        return message.media != null && isRoundVideoDocument(message.media.document);
    }

    public static boolean isPhoto(TLRPC.Message message) {
        if (message.media instanceof TLRPC.TL_messageMediaWebPage) {
            return (message.media.webpage.photo instanceof TLRPC.TL_photo) && !(message.media.webpage.document instanceof TLRPC.TL_document);
        }
        return message.media instanceof TLRPC.TL_messageMediaPhoto;
    }

    public static boolean isVoiceMessage(TLRPC.Message message) {
        if (message.media instanceof TLRPC.TL_messageMediaWebPage) {
            return isVoiceDocument(message.media.webpage.document);
        }
        return message.media != null && isVoiceDocument(message.media.document);
    }

    public static boolean isNewGifMessage(TLRPC.Message message) {
        if (message.media instanceof TLRPC.TL_messageMediaWebPage) {
            return isNewGifDocument(message.media.webpage.document);
        }
        return message.media != null && isNewGifDocument(message.media.document);
    }

    public static boolean isLiveLocationMessage(TLRPC.Message message) {
        return message.media instanceof TLRPC.TL_messageMediaGeoLive;
    }

    public static boolean isVideoMessage(TLRPC.Message message) {
        if (message.media instanceof TLRPC.TL_messageMediaWebPage) {
            return isVideoDocument(message.media.webpage.document);
        }
        return message.media != null && isVideoDocument(message.media.document);
    }

    public static boolean isGameMessage(TLRPC.Message message) {
        return message.media instanceof TLRPC.TL_messageMediaGame;
    }

    public static boolean isInvoiceMessage(TLRPC.Message message) {
        return message.media instanceof TLRPC.TL_messageMediaInvoice;
    }

    public static TLRPC.InputStickerSet getInputStickerSet(TLRPC.Message message) {
        if (message.media != null && message.media.document != null) {
            return getInputStickerSet(message.media.document);
        }
        return null;
    }

    public static TLRPC.InputStickerSet getInputStickerSet(TLRPC.Document document) {
        if (document == null) {
            return null;
        }
        int N = document.attributes.size();
        for (int a = 0; a < N; a++) {
            TLRPC.DocumentAttribute attribute = document.attributes.get(a);
            if (attribute instanceof TLRPC.TL_documentAttributeSticker) {
                if (attribute.stickerset instanceof TLRPC.TL_inputStickerSetEmpty) {
                    return null;
                }
                return attribute.stickerset;
            }
        }
        return null;
    }

    public static long getStickerSetId(TLRPC.Document document) {
        if (document == null) {
            return -1L;
        }
        for (int a = 0; a < document.attributes.size(); a++) {
            TLRPC.DocumentAttribute attribute = document.attributes.get(a);
            if (attribute instanceof TLRPC.TL_documentAttributeSticker) {
                if (attribute.stickerset instanceof TLRPC.TL_inputStickerSetEmpty) {
                    return -1L;
                }
                return attribute.stickerset.id;
            }
        }
        return -1L;
    }

    public String getStrickerChar() {
        TLRPC.Document document = getDocument();
        if (document != null) {
            for (TLRPC.DocumentAttribute attribute : document.attributes) {
                if (attribute instanceof TLRPC.TL_documentAttributeSticker) {
                    return attribute.alt;
                }
            }
            return null;
        }
        return null;
    }

    public int getApproximateHeight() {
        float maxWidth;
        int photoWidth;
        int i = this.type;
        if (i == 0) {
            int height = this.textHeight + (((this.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) && (this.messageOwner.media.webpage instanceof TLRPC.TL_webPage)) ? AndroidUtilities.dp(100.0f) : 0);
            if (isReply()) {
                return height + AndroidUtilities.dp(42.0f);
            }
            return height;
        }
        if (i == 2) {
            return AndroidUtilities.dp(72.0f);
        }
        if (i == 12) {
            return AndroidUtilities.dp(71.0f);
        }
        if (i == 9) {
            return AndroidUtilities.dp(100.0f);
        }
        if (i == 4) {
            return AndroidUtilities.dp(114.0f);
        }
        if (i == 14) {
            return AndroidUtilities.dp(82.0f);
        }
        if (i == 10) {
            return AndroidUtilities.dp(30.0f);
        }
        if (i == 11) {
            return AndroidUtilities.dp(50.0f);
        }
        if (i == 5) {
            return AndroidUtilities.roundMessageSize;
        }
        if (i == 13 || i == 15) {
            float maxHeight = AndroidUtilities.displaySize.y * 0.4f;
            if (AndroidUtilities.isTablet()) {
                maxWidth = AndroidUtilities.getMinTabletSide() * 0.5f;
            } else {
                maxWidth = AndroidUtilities.displaySize.x * 0.5f;
            }
            int photoHeight = 0;
            int photoWidth2 = 0;
            TLRPC.Document document = getDocument();
            int a = 0;
            int N = document.attributes.size();
            while (true) {
                if (a >= N) {
                    break;
                }
                TLRPC.DocumentAttribute attribute = document.attributes.get(a);
                if (!(attribute instanceof TLRPC.TL_documentAttributeImageSize)) {
                    a++;
                } else {
                    photoWidth2 = attribute.w;
                    photoHeight = attribute.h;
                    break;
                }
            }
            if (photoWidth2 == 0) {
                photoHeight = (int) maxHeight;
                photoWidth2 = photoHeight + AndroidUtilities.dp(100.0f);
            }
            if (photoHeight > maxHeight) {
                photoWidth2 = (int) (photoWidth2 * (maxHeight / photoHeight));
                photoHeight = (int) maxHeight;
            }
            if (photoWidth2 > maxWidth) {
                photoHeight = (int) (photoHeight * (maxWidth / photoWidth2));
            }
            return AndroidUtilities.dp(14.0f) + photoHeight;
        }
        if (AndroidUtilities.isTablet()) {
            photoWidth = (int) (AndroidUtilities.getMinTabletSide() * 0.7f);
        } else {
            photoWidth = (int) (Math.min(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y) * 0.7f);
        }
        int photoHeight2 = AndroidUtilities.dp(100.0f) + photoWidth;
        if (photoWidth > AndroidUtilities.getPhotoSize()) {
            photoWidth = AndroidUtilities.getPhotoSize();
        }
        if (photoHeight2 > AndroidUtilities.getPhotoSize()) {
            photoHeight2 = AndroidUtilities.getPhotoSize();
        }
        TLRPC.PhotoSize currentPhotoObject = FileLoader.getClosestPhotoSizeWithSize(this.photoThumbs, AndroidUtilities.getPhotoSize());
        if (currentPhotoObject != null) {
            float scale = currentPhotoObject.w / photoWidth;
            int h = (int) (currentPhotoObject.h / scale);
            if (h == 0) {
                h = AndroidUtilities.dp(100.0f);
            }
            if (h > photoHeight2) {
                h = photoHeight2;
            } else if (h < AndroidUtilities.dp(120.0f)) {
                h = AndroidUtilities.dp(120.0f);
            }
            if (needDrawBluredPreview()) {
                if (AndroidUtilities.isTablet()) {
                    h = (int) (AndroidUtilities.getMinTabletSide() * 0.5f);
                } else {
                    h = (int) (Math.min(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y) * 0.5f);
                }
            }
            photoHeight2 = h;
        }
        return AndroidUtilities.dp(14.0f) + photoHeight2;
    }

    public String getStickerEmoji() {
        TLRPC.Document document = getDocument();
        if (document == null) {
            return null;
        }
        for (int a = 0; a < document.attributes.size(); a++) {
            TLRPC.DocumentAttribute attribute = document.attributes.get(a);
            if (attribute instanceof TLRPC.TL_documentAttributeSticker) {
                if (attribute.alt == null || attribute.alt.length() <= 0) {
                    return null;
                }
                return attribute.alt;
            }
        }
        return null;
    }

    public boolean isAnimatedEmoji() {
        return this.emojiAnimatedSticker != null;
    }

    public boolean isSticker() {
        int i = this.type;
        if (i != 1000) {
            return i == 13;
        }
        return isStickerDocument(getDocument());
    }

    public boolean isAnimatedSticker() {
        int i = this.type;
        if (i != 1000) {
            return i == 15;
        }
        return isAnimatedStickerDocument(getDocument());
    }

    public boolean isAnyKindOfSticker() {
        int i = this.type;
        return i == 13 || i == 15;
    }

    public boolean shouldDrawWithoutBackground() {
        int i = this.type;
        return i == 13 || i == 15 || i == 5;
    }

    public boolean isLocation() {
        return isLocationMessage(this.messageOwner);
    }

    public boolean isMask() {
        return isMaskMessage(this.messageOwner);
    }

    public boolean isMusic() {
        return isMusicMessage(this.messageOwner);
    }

    public boolean isVoice() {
        return isVoiceMessage(this.messageOwner);
    }

    public boolean isVideo() {
        return isVideoMessage(this.messageOwner);
    }

    public boolean isPhoto() {
        return isPhoto(this.messageOwner);
    }

    public boolean isLiveLocation() {
        return isLiveLocationMessage(this.messageOwner);
    }

    public boolean isGame() {
        return isGameMessage(this.messageOwner);
    }

    public boolean isInvoice() {
        return isInvoiceMessage(this.messageOwner);
    }

    public boolean isRoundVideo() {
        if (this.isRoundVideoCached == 0) {
            this.isRoundVideoCached = (this.type == 5 || isRoundVideoMessage(this.messageOwner)) ? 1 : 2;
        }
        return this.isRoundVideoCached == 1;
    }

    public boolean hasPhotoStickers() {
        return (this.messageOwner.media == null || this.messageOwner.media.photo == null || !this.messageOwner.media.photo.has_stickers) ? false : true;
    }

    public boolean isGif() {
        return isGifMessage(this.messageOwner);
    }

    public boolean isWebpageDocument() {
        return (!(this.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) || this.messageOwner.media.webpage.document == null || isGifDocument(this.messageOwner.media.webpage.document)) ? false : true;
    }

    public boolean isWebpage() {
        return this.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage;
    }

    public boolean isNewGif() {
        return this.messageOwner.media != null && isNewGifDocument(this.messageOwner.media.document);
    }

    public boolean isAndroidTheme() {
        if (this.messageOwner.media != null && this.messageOwner.media.webpage != null) {
            ArrayList<TLRPC.Document> documents = this.messageOwner.media.webpage.documents;
            int N = documents.size();
            for (int a = 0; a < N; a++) {
                TLRPC.Document document = documents.get(a);
                if ("application/x-tgtheme-android".equals(document.mime_type)) {
                    return true;
                }
            }
            return false;
        }
        return false;
    }

    public String getMusicTitle() {
        return getMusicTitle(true);
    }

    public String getMusicTitle(boolean unknown) {
        TLRPC.Document document = getDocument();
        if (document != null) {
            for (int a = 0; a < document.attributes.size(); a++) {
                TLRPC.DocumentAttribute attribute = document.attributes.get(a);
                if (attribute instanceof TLRPC.TL_documentAttributeAudio) {
                    if (attribute.voice) {
                        if (!unknown) {
                            return null;
                        }
                        return LocaleController.formatDateAudio(this.messageOwner.date);
                    }
                    String title = attribute.title;
                    if (title == null || title.length() == 0) {
                        String title2 = FileLoader.getDocumentFileName(document);
                        if (TextUtils.isEmpty(title2) && unknown) {
                            return LocaleController.getString("AudioUnknownTitle", mpEIGo.juqQQs.esbSDO.R.string.AudioUnknownTitle);
                        }
                        return title2;
                    }
                    return title;
                }
                if ((attribute instanceof TLRPC.TL_documentAttributeVideo) && attribute.round_message) {
                    return LocaleController.formatDateAudio(this.messageOwner.date);
                }
            }
            String fileName = FileLoader.getDocumentFileName(document);
            if (!TextUtils.isEmpty(fileName)) {
                return fileName;
            }
        }
        return LocaleController.getString("AudioUnknownTitle", mpEIGo.juqQQs.esbSDO.R.string.AudioUnknownTitle);
    }

    public int getDuration() {
        TLRPC.Document document = getDocument();
        if (document == null) {
            return 0;
        }
        int i = this.audioPlayerDuration;
        if (i > 0) {
            return i;
        }
        for (int a = 0; a < document.attributes.size(); a++) {
            TLRPC.DocumentAttribute attribute = document.attributes.get(a);
            if (attribute instanceof TLRPC.TL_documentAttributeAudio) {
                return attribute.duration;
            }
            if (attribute instanceof TLRPC.TL_documentAttributeVideo) {
                return attribute.duration;
            }
        }
        int a2 = this.audioPlayerDuration;
        return a2;
    }

    public String getArtworkUrl(boolean small) {
        TLRPC.Document document = getDocument();
        String str = null;
        if (document != null) {
            int N = document.attributes.size();
            for (int i = 0; i < N; i++) {
                TLRPC.DocumentAttribute attribute = document.attributes.get(i);
                if (attribute instanceof TLRPC.TL_documentAttributeAudio) {
                    if (attribute.voice) {
                        return str;
                    }
                    String performer = attribute.performer;
                    String title = attribute.title;
                    if (!TextUtils.isEmpty(performer)) {
                        int a = 0;
                        while (true) {
                            String[] strArr = excludeWords;
                            if (a >= strArr.length) {
                                break;
                            }
                            performer = performer.replace(strArr[a], " ");
                            a++;
                        }
                    }
                    if (TextUtils.isEmpty(performer) && TextUtils.isEmpty(title)) {
                        return str;
                    }
                    try {
                        StringBuilder sb = new StringBuilder();
                        sb.append("athumb://itunes.apple.com/search?term=");
                        sb.append(URLEncoder.encode(performer + " - " + title, "UTF-8"));
                        sb.append("&entity=song&limit=4");
                        sb.append(small ? "&s=1" : "");
                        return sb.toString();
                    } catch (Exception e) {
                    }
                }
            }
        }
        return str;
    }

    public String getMusicAuthor() {
        return getMusicAuthor(true);
    }

    public String getMusicAuthor(boolean unknown) {
        TLRPC.Document document = getDocument();
        if (document != null) {
            boolean isVoice = false;
            for (int a = 0; a < document.attributes.size(); a++) {
                TLRPC.DocumentAttribute attribute = document.attributes.get(a);
                if (attribute instanceof TLRPC.TL_documentAttributeAudio) {
                    if (attribute.voice) {
                        isVoice = true;
                    } else {
                        String performer = attribute.performer;
                        if (TextUtils.isEmpty(performer) && unknown) {
                            return LocaleController.getString("AudioUnknownArtist", mpEIGo.juqQQs.esbSDO.R.string.AudioUnknownArtist);
                        }
                        return performer;
                    }
                } else if ((attribute instanceof TLRPC.TL_documentAttributeVideo) && attribute.round_message) {
                    isVoice = true;
                }
                if (isVoice) {
                    if (!unknown) {
                        return null;
                    }
                    if (isOutOwner() || (this.messageOwner.fwd_from != null && this.messageOwner.fwd_from.from_id == UserConfig.getInstance(this.currentAccount).getClientUserId())) {
                        return LocaleController.getString("FromYou", mpEIGo.juqQQs.esbSDO.R.string.FromYou);
                    }
                    TLRPC.User user = null;
                    TLRPC.Chat chat = null;
                    if (this.messageOwner.fwd_from != null && this.messageOwner.fwd_from.channel_id != 0) {
                        chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.messageOwner.fwd_from.channel_id));
                    } else if (this.messageOwner.fwd_from != null && this.messageOwner.fwd_from.from_id != 0) {
                        user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.messageOwner.fwd_from.from_id));
                    } else {
                        if (this.messageOwner.fwd_from != null && this.messageOwner.fwd_from.from_name != null) {
                            return this.messageOwner.fwd_from.from_name;
                        }
                        if (this.messageOwner.from_id < 0) {
                            chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(-this.messageOwner.from_id));
                        } else if (this.messageOwner.from_id == 0 && this.messageOwner.to_id.channel_id != 0) {
                            chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.messageOwner.to_id.channel_id));
                        } else {
                            user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.messageOwner.from_id));
                        }
                    }
                    if (user != null) {
                        return UserObject.getName(user);
                    }
                    if (chat != null) {
                        return chat.title;
                    }
                }
            }
        }
        return LocaleController.getString("AudioUnknownArtist", mpEIGo.juqQQs.esbSDO.R.string.AudioUnknownArtist);
    }

    public TLRPC.InputStickerSet getInputStickerSet() {
        return getInputStickerSet(this.messageOwner);
    }

    public boolean isForwarded() {
        return isForwardedMessage(this.messageOwner);
    }

    public boolean needDrawForwarded() {
        return ((this.messageOwner.flags & 4) == 0 || this.messageOwner.fwd_from == null || (this.messageOwner.fwd_from.saved_from_peer != null && this.messageOwner.fwd_from.saved_from_peer.channel_id == this.messageOwner.fwd_from.channel_id) || ((long) UserConfig.getInstance(this.currentAccount).getClientUserId()) == getDialogId()) ? false : true;
    }

    public static boolean isForwardedMessage(TLRPC.Message message) {
        return ((message.flags & 4) == 0 || message.fwd_from == null) ? false : true;
    }

    public boolean isReply() {
        MessageObject messageObject = this.replyMessageObject;
        return (messageObject == null || !(messageObject.messageOwner instanceof TLRPC.TL_messageEmpty)) && !((this.messageOwner.reply_to_msg_id == 0 && this.messageOwner.reply_to_random_id == 0) || (this.messageOwner.flags & 8) == 0);
    }

    public boolean isMediaEmpty() {
        return isMediaEmpty(this.messageOwner);
    }

    public boolean isMediaEmptyWebpage() {
        return isMediaEmptyWebpage(this.messageOwner);
    }

    public static boolean isMediaEmpty(TLRPC.Message message) {
        return message == null || message.media == null || (message.media instanceof TLRPC.TL_messageMediaEmpty) || (message.media instanceof TLRPC.TL_messageMediaWebPage);
    }

    public static boolean isMediaEmptyWebpage(TLRPC.Message message) {
        return message == null || message.media == null || (message.media instanceof TLRPC.TL_messageMediaEmpty);
    }

    public boolean canEditMessage(TLRPC.Chat chat) {
        return canEditMessage(this.currentAccount, this.messageOwner, chat, this.scheduled);
    }

    public boolean canEditMessageScheduleTime(TLRPC.Chat chat) {
        return canEditMessageScheduleTime(this.currentAccount, this.messageOwner, chat);
    }

    public boolean canForwardMessage() {
        int i;
        return ((this.messageOwner instanceof TLRPC.TL_message_secret) || needDrawBluredPreview() || isLiveLocation() || (i = this.type) == 16 || i == 101 || i == 102) ? false : true;
    }

    public boolean canEditMedia() {
        if (isSecretMedia()) {
            return false;
        }
        if (this.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto) {
            return true;
        }
        return (!(this.messageOwner.media instanceof TLRPC.TL_messageMediaDocument) || isVoice() || isSticker() || isAnimatedSticker() || isRoundVideo()) ? false : true;
    }

    public boolean canEditMessageAnytime(TLRPC.Chat chat) {
        return canEditMessageAnytime(this.currentAccount, this.messageOwner, chat);
    }

    public static boolean canEditMessageAnytime(int currentAccount, TLRPC.Message message, TLRPC.Chat chat) {
        if (message == null || message.to_id == null || ((message.media != null && (isRoundVideoDocument(message.media.document) || isStickerDocument(message.media.document) || isAnimatedStickerDocument(message.media.document))) || ((message.action != null && !(message.action instanceof TLRPC.TL_messageActionEmpty)) || isForwardedMessage(message) || message.via_bot_id != 0 || message.id < 0))) {
            return false;
        }
        if (message.from_id == message.to_id.user_id && message.from_id == UserConfig.getInstance(currentAccount).getClientUserId() && !isLiveLocationMessage(message)) {
            return true;
        }
        return !(chat == null && message.to_id.channel_id != 0 && (chat = MessagesController.getInstance(UserConfig.selectedAccount).getChat(Integer.valueOf(message.to_id.channel_id))) == null) && message.out && chat != null && chat.megagroup && (chat.creator || (chat.admin_rights != null && chat.admin_rights.pin_messages));
    }

    public static boolean canEditMessageScheduleTime(int currentAccount, TLRPC.Message message, TLRPC.Chat chat) {
        if (chat == null && message.to_id.channel_id != 0 && (chat = MessagesController.getInstance(currentAccount).getChat(Integer.valueOf(message.to_id.channel_id))) == null) {
            return false;
        }
        if (!ChatObject.isChannel(chat) || chat.megagroup || chat.creator) {
            return true;
        }
        return chat.admin_rights != null && (chat.admin_rights.edit_messages || message.out);
    }

    public static boolean canEditMessage(int currentAccount, TLRPC.Message message, TLRPC.Chat chat, boolean scheduled) {
        if (scheduled && message.date < ConnectionsManager.getInstance(currentAccount).getCurrentTime() - 60) {
            return false;
        }
        if ((chat != null && (chat.left || chat.kicked)) || message == null || message.to_id == null || ((message.media != null && (isRoundVideoDocument(message.media.document) || isStickerDocument(message.media.document) || isAnimatedStickerDocument(message.media.document) || isLocationMessage(message))) || ((message.action != null && !(message.action instanceof TLRPC.TL_messageActionEmpty)) || isForwardedMessage(message) || message.via_bot_id != 0 || message.id < 0))) {
            return false;
        }
        if (message.from_id == message.to_id.user_id && message.from_id == UserConfig.getInstance(currentAccount).getClientUserId() && !isLiveLocationMessage(message) && !(message.media instanceof TLRPC.TL_messageMediaContact)) {
            return true;
        }
        if (chat == null && message.to_id.channel_id != 0 && (chat = MessagesController.getInstance(currentAccount).getChat(Integer.valueOf(message.to_id.channel_id))) == null) {
            return false;
        }
        if (message.media != null && !(message.media instanceof TLRPC.TL_messageMediaEmpty) && !(message.media instanceof TLRPC.TL_messageMediaPhoto) && !(message.media instanceof TLRPC.TL_messageMediaDocument) && !(message.media instanceof TLRPC.TL_messageMediaWebPage)) {
            return false;
        }
        if (message.out && chat != null && chat.megagroup && (chat.creator || (chat.admin_rights != null && chat.admin_rights.pin_messages))) {
            return true;
        }
        if (!scheduled && Math.abs(message.date - ConnectionsManager.getInstance(currentAccount).getCurrentTime()) > MessagesController.getInstance(currentAccount).maxEditTime) {
            return false;
        }
        if (message.to_id.channel_id != 0) {
            return ((chat.megagroup && message.out) || (!chat.megagroup && ((chat.creator || (chat.admin_rights != null && (chat.admin_rights.edit_messages || (message.out && chat.admin_rights.post_messages)))) && message.post))) && ((message.media instanceof TLRPC.TL_messageMediaPhoto) || (!(!(message.media instanceof TLRPC.TL_messageMediaDocument) || isStickerMessage(message) || isAnimatedStickerMessage(message)) || (message.media instanceof TLRPC.TL_messageMediaEmpty) || (message.media instanceof TLRPC.TL_messageMediaWebPage) || message.media == null));
        }
        if (message.out || message.from_id == UserConfig.getInstance(currentAccount).getClientUserId()) {
            return (message.media instanceof TLRPC.TL_messageMediaPhoto) || !(!(message.media instanceof TLRPC.TL_messageMediaDocument) || isStickerMessage(message) || isAnimatedStickerMessage(message)) || (message.media instanceof TLRPC.TL_messageMediaEmpty) || (message.media instanceof TLRPC.TL_messageMediaWebPage) || message.media == null;
        }
        return false;
    }

    public boolean canDeleteMessage(boolean inScheduleMode, TLRPC.Chat chat) {
        return this.eventId == 0 && canDeleteMessage(this.currentAccount, inScheduleMode, this.messageOwner, chat);
    }

    public static boolean canDeleteMessage(int currentAccount, boolean inScheduleMode, TLRPC.Message message, TLRPC.Chat chat) {
        if (message.id < 0) {
            return true;
        }
        if (chat == null && message.to_id.channel_id != 0) {
            chat = MessagesController.getInstance(currentAccount).getChat(Integer.valueOf(message.to_id.channel_id));
        }
        if (!ChatObject.isChannel(chat)) {
            return inScheduleMode || isOut(message) || !ChatObject.isChannel(chat);
        }
        if (inScheduleMode && !chat.megagroup) {
            if (chat.creator) {
                return true;
            }
            return chat.admin_rights != null && (chat.admin_rights.delete_messages || message.out);
        }
        if (inScheduleMode) {
            return true;
        }
        if (message.id != 1) {
            if (chat.creator) {
                return true;
            }
            if (chat.admin_rights != null) {
                if (chat.admin_rights.delete_messages) {
                    return true;
                }
                if (message.out && (chat.megagroup || chat.admin_rights.post_messages)) {
                    return true;
                }
            }
            if (chat.megagroup && message.out && message.from_id > 0) {
                return true;
            }
        }
        return false;
    }

    public String getForwardedName() {
        if (this.messageOwner.fwd_from != null) {
            if (this.messageOwner.fwd_from.channel_id != 0) {
                TLRPC.Chat chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.messageOwner.fwd_from.channel_id));
                if (chat != null) {
                    return chat.title;
                }
                return null;
            }
            if (this.messageOwner.fwd_from.from_id != 0) {
                TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.messageOwner.fwd_from.from_id));
                if (user != null) {
                    return UserObject.getName(user);
                }
                return null;
            }
            if (this.messageOwner.fwd_from.from_name != null) {
                return this.messageOwner.fwd_from.from_name;
            }
            return null;
        }
        return null;
    }

    public int getFromId() {
        if (this.messageOwner.fwd_from != null && this.messageOwner.fwd_from.saved_from_peer != null) {
            if (this.messageOwner.fwd_from.saved_from_peer.user_id != 0) {
                if (this.messageOwner.fwd_from.from_id != 0) {
                    return this.messageOwner.fwd_from.from_id;
                }
                return this.messageOwner.fwd_from.saved_from_peer.user_id;
            }
            if (this.messageOwner.fwd_from.saved_from_peer.channel_id != 0) {
                if (isSavedFromMegagroup() && this.messageOwner.fwd_from.from_id != 0) {
                    return this.messageOwner.fwd_from.from_id;
                }
                if (this.messageOwner.fwd_from.channel_id != 0) {
                    return -this.messageOwner.fwd_from.channel_id;
                }
                return -this.messageOwner.fwd_from.saved_from_peer.channel_id;
            }
            if (this.messageOwner.fwd_from.saved_from_peer.chat_id != 0) {
                if (this.messageOwner.fwd_from.from_id != 0) {
                    return this.messageOwner.fwd_from.from_id;
                }
                if (this.messageOwner.fwd_from.channel_id != 0) {
                    return -this.messageOwner.fwd_from.channel_id;
                }
                return -this.messageOwner.fwd_from.saved_from_peer.chat_id;
            }
            return 0;
        }
        if (this.messageOwner.from_id != 0) {
            return this.messageOwner.from_id;
        }
        if (this.messageOwner.post) {
            return this.messageOwner.to_id.channel_id;
        }
        return 0;
    }

    public boolean isWallpaper() {
        return (this.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) && this.messageOwner.media.webpage != null && "app_background".equals(this.messageOwner.media.webpage.type);
    }

    public int getMediaExistanceFlags() {
        int flags = 0;
        if (this.attachPathExists) {
            flags = 0 | 1;
        }
        if (this.mediaExists) {
            return flags | 2;
        }
        return flags;
    }

    public void applyMediaExistanceFlags(int flags) {
        if (flags == -1) {
            checkMediaExistance();
        } else {
            this.attachPathExists = (flags & 1) != 0;
            this.mediaExists = (flags & 2) != 0;
        }
    }

    public void checkMediaExistance() {
        TLRPC.PhotoSize currentPhotoObject;
        this.attachPathExists = false;
        this.mediaExists = false;
        int i = this.type;
        if (i == 1) {
            if (FileLoader.getClosestPhotoSizeWithSize(this.photoThumbs, AndroidUtilities.getPhotoSize()) != null) {
                File file = FileLoader.getPathToMessage(this.messageOwner);
                if (needDrawBluredPreview()) {
                    this.mediaExists = new File(file.getAbsolutePath() + ".enc").exists();
                }
                if (!this.mediaExists) {
                    this.mediaExists = file.exists();
                    return;
                }
                return;
            }
            return;
        }
        if (i == 8 || i == 3 || i == 9 || i == 2 || i == 14 || i == 5) {
            if (this.messageOwner.attachPath != null && this.messageOwner.attachPath.length() > 0) {
                File f = new File(this.messageOwner.attachPath);
                this.attachPathExists = f.exists();
            }
            if (!this.attachPathExists) {
                File file2 = FileLoader.getPathToMessage(this.messageOwner);
                if (this.type == 3 && needDrawBluredPreview()) {
                    this.mediaExists = new File(file2.getAbsolutePath() + ".enc").exists();
                }
                if (!this.mediaExists) {
                    this.mediaExists = file2.exists();
                    return;
                }
                return;
            }
            return;
        }
        TLRPC.Document document = getDocument();
        if (document != null) {
            if (isWallpaper()) {
                this.mediaExists = FileLoader.getPathToAttach(document, true).exists();
                return;
            } else {
                this.mediaExists = FileLoader.getPathToAttach(document).exists();
                return;
            }
        }
        if (this.type == 0 && (currentPhotoObject = FileLoader.getClosestPhotoSizeWithSize(this.photoThumbs, AndroidUtilities.getPhotoSize())) != null && currentPhotoObject != null) {
            this.mediaExists = FileLoader.getPathToAttach(currentPhotoObject, true).exists();
        }
    }

    public boolean equals(MessageObject obj) {
        return getId() == obj.getId() && getDialogId() == obj.getDialogId();
    }
}
