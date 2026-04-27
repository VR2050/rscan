package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.TextPaint;
import android.text.TextUtils;
import android.util.SparseArray;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.DispatchQueue;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChatRightsEditActivity;
import im.uwrkaxlmjj.ui.GroupCreateActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper;
import im.uwrkaxlmjj.ui.cells.GraySectionCell;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.ManageChatTextCell;
import im.uwrkaxlmjj.ui.cells.ManageChatUserCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextCheckCell2;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.UndoView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChatUsersActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    public static final int TYPE_ADMIN = 1;
    public static final int TYPE_BANNED = 0;
    public static final int TYPE_KICKED = 3;
    public static final int TYPE_USERS = 2;
    private static final int done_button = 1;
    private static final int search_button = 0;
    private int addNew2Row;
    private int addNewRow;
    private int addNewSectionRow;
    private int addUsersRow;
    private int blockedEmptyRow;
    private int botEndRow;
    private int botHeaderRow;
    private int botStartRow;
    private ArrayList<TLObject> bots;
    private boolean botsEndReached;
    private SparseArray<TLObject> botsMap;
    private int changeInfoRow;
    private int chatId;
    private ArrayList<TLObject> contacts;
    private boolean contactsEndReached;
    private int contactsEndRow;
    private int contactsHeaderRow;
    private SparseArray<TLObject> contactsMap;
    private int contactsStartRow;
    private TLRPC.Chat currentChat;
    private TLRPC.TL_chatBannedRights defaultBannedRights;
    private int delayResults;
    private ChatUsersActivityDelegate delegate;
    private ActionBarMenuItem doneItem;
    private int embedLinksRow;
    private EmptyTextProgressView emptyView;
    private boolean firstLoaded;
    private TLRPC.ChatFull info;
    private String initialBannedRights;
    private int initialSlowmode;
    private boolean isChannel;
    private RecyclerListView listView;
    private ListAdapter listViewAdapter;
    private boolean loadingUsers;
    private int membersHeaderRow;
    private boolean needOpenSearch;
    private ArrayList<TLObject> participants;
    private int participantsDivider2Row;
    private int participantsDividerRow;
    private int participantsEndRow;
    private int participantsInfoRow;
    private SparseArray<TLObject> participantsMap;
    private int participantsStartRow;
    private int permissionsSectionRow;
    private int pinMessagesRow;
    private int recentActionsRow;
    private int removedUsersRow;
    private int restricted1SectionRow;
    private int rowCount;
    private ActionBarMenuItem searchItem;
    private SearchAdapter searchListViewAdapter;
    private boolean searchWas;
    private boolean searching;
    private int selectType;
    private int selectedSlowmode;
    private int sendMediaRow;
    private int sendMessagesRow;
    private int sendPollsRow;
    private int sendStickersRow;
    private int slowmodeInfoRow;
    private int slowmodeRow;
    private int slowmodeSelectRow;
    private int type;
    private UndoView undoView;

    public interface ChatUsersActivityDelegate {
        void didAddParticipantToList(int i, TLObject tLObject);

        void didChangeOwner(TLRPC.User user);
    }

    private class ChooseView extends View {
        private int circleSize;
        private int gapSize;
        private int lineSize;
        private boolean moving;
        private Paint paint;
        private int sideSide;
        private ArrayList<Integer> sizes;
        private boolean startMoving;
        private int startMovingItem;
        private float startX;
        private ArrayList<String> strings;
        private TextPaint textPaint;

        public ChooseView(Context context) {
            String string;
            super(context);
            this.strings = new ArrayList<>();
            this.sizes = new ArrayList<>();
            this.paint = new Paint(1);
            TextPaint textPaint = new TextPaint(1);
            this.textPaint = textPaint;
            textPaint.setTextSize(AndroidUtilities.dp(13.0f));
            for (int a = 0; a < 7; a++) {
                if (a == 0) {
                    string = LocaleController.getString("SlowmodeOff", R.string.SlowmodeOff);
                } else if (a == 1) {
                    string = LocaleController.formatString("SlowmodeSeconds", R.string.SlowmodeSeconds, 10);
                } else if (a == 2) {
                    string = LocaleController.formatString("SlowmodeSeconds", R.string.SlowmodeSeconds, 30);
                } else if (a == 3) {
                    string = LocaleController.formatString("SlowmodeMinutes", R.string.SlowmodeMinutes, 1);
                } else if (a == 4) {
                    string = LocaleController.formatString("SlowmodeMinutes", R.string.SlowmodeMinutes, 5);
                } else if (a == 5) {
                    string = LocaleController.formatString("SlowmodeMinutes", R.string.SlowmodeMinutes, 15);
                } else {
                    string = LocaleController.formatString("SlowmodeHours", R.string.SlowmodeHours, 1);
                }
                this.strings.add(string);
                this.sizes.add(Integer.valueOf((int) Math.ceil(this.textPaint.measureText(string))));
            }
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            float x = event.getX();
            if (event.getAction() == 0) {
                getParent().requestDisallowInterceptTouchEvent(true);
                int a = 0;
                while (true) {
                    if (a >= this.strings.size()) {
                        break;
                    }
                    int i = this.sideSide;
                    int i2 = this.lineSize + (this.gapSize * 2);
                    int i3 = this.circleSize;
                    int cx = i + ((i2 + i3) * a) + (i3 / 2);
                    if (x > cx - AndroidUtilities.dp(15.0f) && x < AndroidUtilities.dp(15.0f) + cx) {
                        this.startMoving = a == ChatUsersActivity.this.selectedSlowmode;
                        this.startX = x;
                        this.startMovingItem = ChatUsersActivity.this.selectedSlowmode;
                    } else {
                        a++;
                    }
                }
            } else if (event.getAction() == 2) {
                if (this.startMoving) {
                    if (Math.abs(this.startX - x) >= AndroidUtilities.getPixelsInCM(0.5f, true)) {
                        this.moving = true;
                        this.startMoving = false;
                    }
                } else if (this.moving) {
                    int a2 = 0;
                    while (true) {
                        if (a2 >= this.strings.size()) {
                            break;
                        }
                        int i4 = this.sideSide;
                        int i5 = this.lineSize;
                        int i6 = this.gapSize;
                        int i7 = this.circleSize;
                        int cx2 = i4 + (((i6 * 2) + i5 + i7) * a2) + (i7 / 2);
                        int diff = (i5 / 2) + (i7 / 2) + i6;
                        if (x > cx2 - diff && x < cx2 + diff) {
                            if (ChatUsersActivity.this.selectedSlowmode != a2) {
                                setItem(a2);
                            }
                        } else {
                            a2++;
                        }
                    }
                }
            } else if (event.getAction() == 1 || event.getAction() == 3) {
                if (this.moving) {
                    if (ChatUsersActivity.this.selectedSlowmode != this.startMovingItem) {
                        setItem(ChatUsersActivity.this.selectedSlowmode);
                    }
                } else {
                    int a3 = 0;
                    while (true) {
                        if (a3 >= this.strings.size()) {
                            break;
                        }
                        int i8 = this.sideSide;
                        int i9 = this.lineSize + (this.gapSize * 2);
                        int i10 = this.circleSize;
                        int cx3 = i8 + ((i9 + i10) * a3) + (i10 / 2);
                        if (x > cx3 - AndroidUtilities.dp(15.0f) && x < AndroidUtilities.dp(15.0f) + cx3) {
                            if (ChatUsersActivity.this.selectedSlowmode != a3) {
                                setItem(a3);
                            }
                        } else {
                            a3++;
                        }
                    }
                }
                this.startMoving = false;
                this.moving = false;
            }
            return true;
        }

        private void setItem(int index) {
            if (ChatUsersActivity.this.info != null) {
                ChatUsersActivity.this.selectedSlowmode = index;
                ChatUsersActivity.this.info.slowmode_seconds = ChatUsersActivity.this.getSecondsForIndex(index);
                ChatUsersActivity.this.info.flags |= 131072;
                for (int a = 0; a < 3; a++) {
                    RecyclerView.ViewHolder holder = ChatUsersActivity.this.listView.findViewHolderForAdapterPosition(ChatUsersActivity.this.slowmodeInfoRow);
                    if (holder != null) {
                        ChatUsersActivity.this.listViewAdapter.onBindViewHolder(holder, ChatUsersActivity.this.slowmodeInfoRow);
                    }
                }
                invalidate();
            }
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(74.0f), 1073741824));
            View.MeasureSpec.getSize(widthMeasureSpec);
            this.circleSize = AndroidUtilities.dp(6.0f);
            this.gapSize = AndroidUtilities.dp(2.0f);
            this.sideSide = AndroidUtilities.dp(22.0f);
            this.lineSize = (((getMeasuredWidth() - (this.circleSize * this.strings.size())) - ((this.gapSize * 2) * (this.strings.size() - 1))) - (this.sideSide * 2)) / (this.strings.size() - 1);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            this.textPaint.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
            int cy = (getMeasuredHeight() / 2) + AndroidUtilities.dp(11.0f);
            int a = 0;
            while (a < this.strings.size()) {
                int i = this.sideSide;
                int i2 = this.lineSize + (this.gapSize * 2);
                int i3 = this.circleSize;
                int cx = i + ((i2 + i3) * a) + (i3 / 2);
                if (a <= ChatUsersActivity.this.selectedSlowmode) {
                    this.paint.setColor(Theme.getColor(Theme.key_switchTrackChecked));
                } else {
                    this.paint.setColor(Theme.getColor(Theme.key_switchTrack));
                }
                canvas.drawCircle(cx, cy, a == ChatUsersActivity.this.selectedSlowmode ? AndroidUtilities.dp(6.0f) : this.circleSize / 2, this.paint);
                if (a != 0) {
                    int x = ((cx - (this.circleSize / 2)) - this.gapSize) - this.lineSize;
                    int width = this.lineSize;
                    if (a == ChatUsersActivity.this.selectedSlowmode || a == ChatUsersActivity.this.selectedSlowmode + 1) {
                        width -= AndroidUtilities.dp(3.0f);
                    }
                    if (a == ChatUsersActivity.this.selectedSlowmode + 1) {
                        x += AndroidUtilities.dp(3.0f);
                    }
                    canvas.drawRect(x, cy - AndroidUtilities.dp(1.0f), x + width, AndroidUtilities.dp(1.0f) + cy, this.paint);
                }
                int size = this.sizes.get(a).intValue();
                String text = this.strings.get(a);
                if (a == 0) {
                    canvas.drawText(text, AndroidUtilities.dp(22.0f), AndroidUtilities.dp(28.0f), this.textPaint);
                } else if (a == this.strings.size() - 1) {
                    canvas.drawText(text, (getMeasuredWidth() - size) - AndroidUtilities.dp(22.0f), AndroidUtilities.dp(28.0f), this.textPaint);
                } else {
                    canvas.drawText(text, cx - (size / 2), AndroidUtilities.dp(28.0f), this.textPaint);
                }
                a++;
            }
        }
    }

    public ChatUsersActivity(Bundle args) {
        super(args);
        this.defaultBannedRights = new TLRPC.TL_chatBannedRights();
        this.participants = new ArrayList<>();
        this.bots = new ArrayList<>();
        this.contacts = new ArrayList<>();
        this.participantsMap = new SparseArray<>();
        this.botsMap = new SparseArray<>();
        this.contactsMap = new SparseArray<>();
        this.chatId = this.arguments.getInt("chat_id");
        this.type = this.arguments.getInt("type");
        this.needOpenSearch = this.arguments.getBoolean("open_search");
        this.selectType = this.arguments.getInt("selectType");
        TLRPC.Chat chat = getMessagesController().getChat(Integer.valueOf(this.chatId));
        this.currentChat = chat;
        if (chat != null && chat.default_banned_rights != null) {
            this.defaultBannedRights.view_messages = this.currentChat.default_banned_rights.view_messages;
            this.defaultBannedRights.send_stickers = this.currentChat.default_banned_rights.send_stickers;
            this.defaultBannedRights.send_media = this.currentChat.default_banned_rights.send_media;
            this.defaultBannedRights.embed_links = this.currentChat.default_banned_rights.embed_links;
            this.defaultBannedRights.send_messages = this.currentChat.default_banned_rights.send_messages;
            this.defaultBannedRights.send_games = this.currentChat.default_banned_rights.send_games;
            this.defaultBannedRights.send_inline = this.currentChat.default_banned_rights.send_inline;
            this.defaultBannedRights.send_gifs = this.currentChat.default_banned_rights.send_gifs;
            this.defaultBannedRights.pin_messages = this.currentChat.default_banned_rights.pin_messages;
            this.defaultBannedRights.send_polls = this.currentChat.default_banned_rights.send_polls;
            this.defaultBannedRights.invite_users = this.currentChat.default_banned_rights.invite_users;
            this.defaultBannedRights.change_info = this.currentChat.default_banned_rights.change_info;
        }
        this.initialBannedRights = ChatObject.getBannedRightsString(this.defaultBannedRights);
        this.isChannel = ChatObject.isChannel(this.currentChat) && !this.currentChat.megagroup;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateRows() {
        TLRPC.ChatFull chatFull;
        TLRPC.Chat chat = getMessagesController().getChat(Integer.valueOf(this.chatId));
        this.currentChat = chat;
        if (chat == null) {
            return;
        }
        this.recentActionsRow = -1;
        this.addNewRow = -1;
        this.addNew2Row = -1;
        this.addNewSectionRow = -1;
        this.restricted1SectionRow = -1;
        this.participantsStartRow = -1;
        this.participantsDividerRow = -1;
        this.participantsDivider2Row = -1;
        this.participantsEndRow = -1;
        this.participantsInfoRow = -1;
        this.blockedEmptyRow = -1;
        this.permissionsSectionRow = -1;
        this.sendMessagesRow = -1;
        this.sendMediaRow = -1;
        this.sendStickersRow = -1;
        this.sendPollsRow = -1;
        this.embedLinksRow = -1;
        this.addUsersRow = -1;
        this.pinMessagesRow = -1;
        this.changeInfoRow = -1;
        this.removedUsersRow = -1;
        this.contactsHeaderRow = -1;
        this.contactsStartRow = -1;
        this.contactsEndRow = -1;
        this.botHeaderRow = -1;
        this.botStartRow = -1;
        this.botEndRow = -1;
        this.membersHeaderRow = -1;
        this.slowmodeRow = -1;
        this.slowmodeSelectRow = -1;
        this.slowmodeInfoRow = -1;
        this.rowCount = 0;
        int i = this.type;
        if (i == 3) {
            int i2 = 0 + 1;
            this.rowCount = i2;
            this.permissionsSectionRow = 0;
            int i3 = i2 + 1;
            this.rowCount = i3;
            this.sendMessagesRow = i2;
            int i4 = i3 + 1;
            this.rowCount = i4;
            this.sendMediaRow = i3;
            int i5 = i4 + 1;
            this.rowCount = i5;
            this.sendStickersRow = i4;
            int i6 = i5 + 1;
            this.rowCount = i6;
            this.sendPollsRow = i5;
            int i7 = i6 + 1;
            this.rowCount = i7;
            this.embedLinksRow = i6;
            int i8 = i7 + 1;
            this.rowCount = i8;
            this.addUsersRow = i7;
            int i9 = i8 + 1;
            this.rowCount = i9;
            this.pinMessagesRow = i8;
            this.rowCount = i9 + 1;
            this.changeInfoRow = i9;
            if ((!ChatObject.isChannel(chat) && this.currentChat.creator) || (this.currentChat.megagroup && ChatObject.canBlockUsers(this.currentChat))) {
                int i10 = this.rowCount;
                int i11 = i10 + 1;
                this.rowCount = i11;
                this.participantsDivider2Row = i10;
                int i12 = i11 + 1;
                this.rowCount = i12;
                this.slowmodeRow = i11;
                int i13 = i12 + 1;
                this.rowCount = i13;
                this.slowmodeSelectRow = i12;
                this.rowCount = i13 + 1;
                this.slowmodeInfoRow = i13;
            }
            if (ChatObject.isChannel(this.currentChat)) {
                if (this.participantsDivider2Row == -1) {
                    int i14 = this.rowCount;
                    this.rowCount = i14 + 1;
                    this.participantsDivider2Row = i14;
                }
                int i15 = this.rowCount;
                this.rowCount = i15 + 1;
                this.removedUsersRow = i15;
            }
            int i16 = this.rowCount;
            this.rowCount = i16 + 1;
            this.participantsDividerRow = i16;
            if (ChatObject.canBlockUsers(this.currentChat)) {
                int i17 = this.rowCount;
                this.rowCount = i17 + 1;
                this.addNewRow = i17;
            }
            if (!this.participants.isEmpty()) {
                int i18 = this.rowCount;
                this.participantsStartRow = i18;
                int size = i18 + this.participants.size();
                this.rowCount = size;
                this.participantsEndRow = size;
                return;
            }
            return;
        }
        if (i == 0) {
            if (ChatObject.canBlockUsers(chat)) {
                int i19 = this.rowCount;
                this.rowCount = i19 + 1;
                this.addNewRow = i19;
                if (!this.participants.isEmpty()) {
                    int i20 = this.rowCount;
                    this.rowCount = i20 + 1;
                    this.participantsInfoRow = i20;
                }
            }
            if (!this.participants.isEmpty()) {
                int i21 = this.rowCount;
                int i22 = i21 + 1;
                this.rowCount = i22;
                this.restricted1SectionRow = i21;
                this.participantsStartRow = i22;
                int size2 = i22 + this.participants.size();
                this.rowCount = size2;
                this.participantsEndRow = size2;
            }
            if (this.participantsStartRow != -1) {
                if (this.participantsInfoRow == -1) {
                    int i23 = this.rowCount;
                    this.rowCount = i23 + 1;
                    this.participantsInfoRow = i23;
                    return;
                }
                return;
            }
            int i24 = this.rowCount;
            this.rowCount = i24 + 1;
            this.blockedEmptyRow = i24;
            return;
        }
        if (i == 1) {
            if (ChatObject.isChannel(chat) && this.currentChat.megagroup && ((chatFull = this.info) == null || chatFull.participants_count <= 200)) {
                int i25 = this.rowCount;
                int i26 = i25 + 1;
                this.rowCount = i26;
                this.recentActionsRow = i25;
                this.rowCount = i26 + 1;
                this.addNewSectionRow = i26;
            }
            if (ChatObject.canAddAdmins(this.currentChat)) {
                int i27 = this.rowCount;
                this.rowCount = i27 + 1;
                this.addNewRow = i27;
            }
            if (!this.participants.isEmpty()) {
                int i28 = this.rowCount;
                this.participantsStartRow = i28;
                int size3 = i28 + this.participants.size();
                this.rowCount = size3;
                this.participantsEndRow = size3;
            }
            if (this.currentChat.creator) {
                int i29 = this.rowCount;
                this.rowCount = i29 + 1;
                this.participantsInfoRow = i29;
                return;
            }
            return;
        }
        if (i == 2) {
            if (this.selectType == 0 && ChatObject.canAddUsers(chat)) {
                int i30 = this.rowCount;
                this.rowCount = i30 + 1;
                this.addNewRow = i30;
            }
            boolean hasAnyOther = false;
            if (!this.contacts.isEmpty()) {
                int i31 = this.rowCount;
                int i32 = i31 + 1;
                this.rowCount = i32;
                this.contactsHeaderRow = i31;
                this.contactsStartRow = i32;
                int size4 = i32 + this.contacts.size();
                this.rowCount = size4;
                this.contactsEndRow = size4;
                hasAnyOther = true;
            }
            if (!this.bots.isEmpty()) {
                int i33 = this.rowCount;
                int i34 = i33 + 1;
                this.rowCount = i34;
                this.botHeaderRow = i33;
                this.botStartRow = i34;
                int size5 = i34 + this.bots.size();
                this.rowCount = size5;
                this.botEndRow = size5;
                hasAnyOther = true;
            }
            if (!this.participants.isEmpty()) {
                if (hasAnyOther) {
                    int i35 = this.rowCount;
                    this.rowCount = i35 + 1;
                    this.membersHeaderRow = i35;
                }
                int i36 = this.rowCount;
                this.participantsStartRow = i36;
                int size6 = i36 + this.participants.size();
                this.rowCount = size6;
                this.participantsEndRow = size6;
            }
            int i37 = this.rowCount;
            if (i37 != 0 && this.isChannel && this.selectType == 0) {
                this.rowCount = i37 + 1;
                this.participantsInfoRow = i37;
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        getNotificationCenter().addObserver(this, NotificationCenter.chatInfoDidLoad);
        loadChatParticipants(0, ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        getNotificationCenter().removeObserver(this, NotificationCenter.chatInfoDidLoad);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        int i;
        this.searching = false;
        this.searchWas = false;
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        int i2 = this.type;
        if (i2 == 3) {
            this.actionBar.setTitle(LocaleController.getString("ChannelPermissions", R.string.ChannelPermissions));
        } else if (i2 == 0) {
            this.actionBar.setTitle(LocaleController.getString("ChannelBlacklist", R.string.ChannelBlacklist));
        } else if (i2 == 1) {
            this.actionBar.setTitle(LocaleController.getString("ChannelAdministrators", R.string.ChannelAdministrators));
        } else if (i2 == 2) {
            int i3 = this.selectType;
            if (i3 == 0) {
                if (this.isChannel) {
                    this.actionBar.setTitle(LocaleController.getString("ChannelSubscribers", R.string.ChannelSubscribers));
                } else {
                    this.actionBar.setTitle(LocaleController.getString("ChannelMembers", R.string.ChannelMembers));
                }
            } else if (i3 == 1) {
                this.actionBar.setTitle(LocaleController.getString("ChannelAddAdmin", R.string.ChannelAddAdmin));
            } else if (i3 == 2) {
                this.actionBar.setTitle(LocaleController.getString("ChannelBlockUser", R.string.ChannelBlockUser));
            } else if (i3 == 3) {
                this.actionBar.setTitle(LocaleController.getString("ChannelAddException", R.string.ChannelAddException));
            }
        }
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.ChatUsersActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    if (ChatUsersActivity.this.checkDiscard()) {
                        ChatUsersActivity.this.finishFragment();
                    }
                } else if (id == 1) {
                    ChatUsersActivity.this.processDone();
                }
            }
        });
        if (this.selectType != 0 || (i = this.type) == 2 || i == 0 || i == 3) {
            this.searchListViewAdapter = new SearchAdapter(context);
            ActionBarMenu menu = this.actionBar.createMenu();
            ActionBarMenuItem actionBarMenuItemSearchListener = menu.addItem(0, R.drawable.ic_ab_search).setIsSearchField(true).setActionBarMenuItemSearchListener(new ActionBarMenuItem.ActionBarMenuItemSearchListener() { // from class: im.uwrkaxlmjj.ui.ChatUsersActivity.2
                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
                public void onSearchExpand() {
                    ChatUsersActivity.this.searching = true;
                    ChatUsersActivity.this.emptyView.setShowAtCenter(true);
                    if (ChatUsersActivity.this.doneItem != null) {
                        ChatUsersActivity.this.doneItem.setVisibility(8);
                    }
                }

                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
                public void onSearchCollapse() {
                    ChatUsersActivity.this.searchListViewAdapter.searchDialogs(null);
                    ChatUsersActivity.this.searching = false;
                    ChatUsersActivity.this.searchWas = false;
                    ChatUsersActivity.this.listView.setAdapter(ChatUsersActivity.this.listViewAdapter);
                    ChatUsersActivity.this.listViewAdapter.notifyDataSetChanged();
                    ChatUsersActivity.this.listView.setFastScrollVisible(true);
                    ChatUsersActivity.this.listView.setVerticalScrollBarEnabled(false);
                    ChatUsersActivity.this.emptyView.setShowAtCenter(false);
                    if (ChatUsersActivity.this.doneItem != null) {
                        ChatUsersActivity.this.doneItem.setVisibility(0);
                    }
                }

                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
                public void onTextChanged(EditText editText) {
                    if (ChatUsersActivity.this.searchListViewAdapter == null) {
                        return;
                    }
                    String text = editText.getText().toString();
                    if (text.length() != 0) {
                        ChatUsersActivity.this.searchWas = true;
                        if (ChatUsersActivity.this.listView != null && ChatUsersActivity.this.listView.getAdapter() != ChatUsersActivity.this.searchListViewAdapter) {
                            ChatUsersActivity.this.listView.setAdapter(ChatUsersActivity.this.searchListViewAdapter);
                            ChatUsersActivity.this.searchListViewAdapter.notifyDataSetChanged();
                            ChatUsersActivity.this.listView.setFastScrollVisible(false);
                            ChatUsersActivity.this.listView.setVerticalScrollBarEnabled(true);
                        }
                    }
                    ChatUsersActivity.this.searchListViewAdapter.searchDialogs(text);
                }
            });
            this.searchItem = actionBarMenuItemSearchListener;
            if (this.type == 3) {
                actionBarMenuItemSearchListener.setSearchFieldHint(LocaleController.getString("ChannelSearchException", R.string.ChannelSearchException));
            } else {
                actionBarMenuItemSearchListener.setSearchFieldHint(LocaleController.getString("Search", R.string.Search));
            }
            if (this.type == 3) {
                this.doneItem = menu.addItemWithWidth(1, R.drawable.ic_done, AndroidUtilities.dp(56.0f), LocaleController.getString("Done", R.string.Done));
            }
        }
        this.fragmentView = new FrameLayout(context);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        this.emptyView = new EmptyTextProgressView(context);
        int i4 = this.type;
        if (i4 == 0 || i4 == 2 || i4 == 3) {
            this.emptyView.setText(LocaleController.getString("NoResult", R.string.NoResult));
        }
        this.emptyView.setShowAtCenter(true);
        frameLayout.addView(this.emptyView, LayoutHelper.createFrame(-1, -1.0f));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setEmptyView(this.emptyView);
        this.listView.setLayoutManager(new LinearLayoutManager(context, 1, false));
        RecyclerListView recyclerListView2 = this.listView;
        ListAdapter listAdapter = new ListAdapter(context);
        this.listViewAdapter = listAdapter;
        recyclerListView2.setAdapter(listAdapter);
        this.listView.setVerticalScrollbarPosition(LocaleController.isRTL ? 1 : 2);
        this.listView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -2, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f)));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$kQehE7eGKwPbspj1wtcmDOdXGco
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i5) {
                this.f$0.lambda$createView$2$ChatUsersActivity(view, i5);
            }
        });
        this.listView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$fn1IKfq_412XkmReSWisPqNXKEo
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
            public final boolean onItemClick(View view, int i5) {
                return this.f$0.lambda$createView$3$ChatUsersActivity(view, i5);
            }
        });
        if (this.searchItem != null) {
            this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.ChatUsersActivity.6
                @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
                public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                    if (newState == 1) {
                        AndroidUtilities.hideKeyboard(ChatUsersActivity.this.getParentActivity().getCurrentFocus());
                    }
                }

                @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
                public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                }
            });
        }
        UndoView undoView = new UndoView(context);
        this.undoView = undoView;
        frameLayout.addView(undoView, LayoutHelper.createFrame(-1.0f, -2.0f, 83, 8.0f, 0.0f, 8.0f, 8.0f));
        if (this.loadingUsers) {
            this.emptyView.showProgress();
        } else {
            this.emptyView.showTextView();
        }
        updateRows();
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$2$ChatUsersActivity(View view, int position) {
        TLObject participant;
        TLRPC.TL_chatBannedRights bannedRights;
        String rank;
        boolean canEditAdmin;
        TLObject participant2;
        TLRPC.TL_chatAdminRights adminRights;
        int user_id;
        boolean z;
        TLRPC.Chat chat;
        int i;
        TLObject participant3;
        boolean listAdapter = this.listView.getAdapter() == this.listViewAdapter;
        if (listAdapter) {
            if (position == this.addNewRow) {
                int i2 = this.type;
                if (i2 == 0 || i2 == 3) {
                    Bundle bundle = new Bundle();
                    bundle.putInt("chat_id", this.chatId);
                    bundle.putInt("type", 2);
                    bundle.putInt("selectType", this.type == 0 ? 2 : 3);
                    ChatUsersActivity fragment = new ChatUsersActivity(bundle);
                    fragment.setInfo(this.info);
                    presentFragment(fragment);
                    return;
                }
                if (i2 == 1) {
                    Bundle bundle2 = new Bundle();
                    bundle2.putInt("chat_id", this.chatId);
                    bundle2.putInt("type", 2);
                    bundle2.putInt("selectType", 1);
                    ChatUsersActivity fragment2 = new ChatUsersActivity(bundle2);
                    fragment2.setDelegate(new AnonymousClass3());
                    fragment2.setInfo(this.info);
                    presentFragment(fragment2);
                    return;
                }
                if (i2 == 2) {
                    Bundle args = new Bundle();
                    args.putBoolean("addToGroup", true);
                    args.putInt(this.isChannel ? "channelId" : "chatId", this.currentChat.id);
                    GroupCreateActivity fragment3 = new GroupCreateActivity(args);
                    fragment3.setInfo(this.info);
                    SparseArray<TLObject> sparseArray = this.contactsMap;
                    fragment3.setIgnoreUsers((sparseArray == null || sparseArray.size() == 0) ? this.participantsMap : this.contactsMap);
                    fragment3.setDelegate(new GroupCreateActivity.ContactsAddActivityDelegate() { // from class: im.uwrkaxlmjj.ui.ChatUsersActivity.4
                        @Override // im.uwrkaxlmjj.ui.GroupCreateActivity.ContactsAddActivityDelegate
                        public void didSelectUsers(ArrayList<TLRPC.User> arrayList, int fwdCount) {
                            int N = arrayList.size();
                            for (int a = 0; a < N; a++) {
                                TLRPC.User user = arrayList.get(a);
                                ChatUsersActivity.this.getMessagesController().addUserToChat(ChatUsersActivity.this.chatId, user, null, fwdCount, null, ChatUsersActivity.this, null);
                            }
                        }

                        @Override // im.uwrkaxlmjj.ui.GroupCreateActivity.ContactsAddActivityDelegate
                        public void needAddBot(TLRPC.User user) {
                            ChatUsersActivity.this.openRightsEdit(user.id, null, null, null, "", true, 0, false);
                        }
                    });
                    presentFragment(fragment3);
                    return;
                }
                return;
            }
            if (position == this.recentActionsRow) {
                presentFragment(new ChannelAdminLogActivity(this.currentChat));
                return;
            }
            if (position == this.removedUsersRow) {
                Bundle args2 = new Bundle();
                args2.putInt("chat_id", this.chatId);
                args2.putInt("type", 0);
                ChatUsersActivity fragment4 = new ChatUsersActivity(args2);
                fragment4.setInfo(this.info);
                presentFragment(fragment4);
                return;
            }
            if (position == this.addNew2Row) {
                presentFragment(new GroupInviteActivity(this.chatId));
                return;
            }
            if (position > this.permissionsSectionRow && position <= this.changeInfoRow) {
                TextCheckCell2 checkCell = (TextCheckCell2) view;
                if (!checkCell.isEnabled()) {
                    return;
                }
                if (checkCell.hasIcon()) {
                    if (!TextUtils.isEmpty(this.currentChat.username) && (position == this.pinMessagesRow || position == this.changeInfoRow)) {
                        ToastUtils.show(R.string.EditCantEditPermissionsPublic);
                        return;
                    } else {
                        ToastUtils.show(R.string.EditCantEditPermissions);
                        return;
                    }
                }
                checkCell.setChecked(!checkCell.isChecked());
                if (position == this.changeInfoRow) {
                    this.defaultBannedRights.change_info = !r1.change_info;
                    return;
                }
                if (position == this.addUsersRow) {
                    this.defaultBannedRights.invite_users = !r1.invite_users;
                    return;
                }
                if (position == this.pinMessagesRow) {
                    this.defaultBannedRights.pin_messages = !r1.pin_messages;
                    return;
                }
                boolean disabled = !checkCell.isChecked();
                if (position == this.sendMessagesRow) {
                    this.defaultBannedRights.send_messages = !r4.send_messages;
                } else if (position == this.sendMediaRow) {
                    this.defaultBannedRights.send_media = !r4.send_media;
                } else if (position == this.sendStickersRow) {
                    TLRPC.TL_chatBannedRights tL_chatBannedRights = this.defaultBannedRights;
                    boolean z2 = !tL_chatBannedRights.send_stickers;
                    tL_chatBannedRights.send_inline = z2;
                    tL_chatBannedRights.send_gifs = z2;
                    tL_chatBannedRights.send_games = z2;
                    tL_chatBannedRights.send_stickers = z2;
                } else if (position == this.embedLinksRow) {
                    this.defaultBannedRights.embed_links = !r4.embed_links;
                } else if (position == this.sendPollsRow) {
                    this.defaultBannedRights.send_polls = !r4.send_polls;
                }
                if (disabled) {
                    if (this.defaultBannedRights.view_messages && !this.defaultBannedRights.send_messages) {
                        this.defaultBannedRights.send_messages = true;
                        RecyclerView.ViewHolder holder = this.listView.findViewHolderForAdapterPosition(this.sendMessagesRow);
                        if (holder != null) {
                            ((TextCheckCell2) holder.itemView).setChecked(false);
                        }
                    }
                    if ((this.defaultBannedRights.view_messages || this.defaultBannedRights.send_messages) && !this.defaultBannedRights.send_media) {
                        this.defaultBannedRights.send_media = true;
                        RecyclerView.ViewHolder holder2 = this.listView.findViewHolderForAdapterPosition(this.sendMediaRow);
                        if (holder2 != null) {
                            ((TextCheckCell2) holder2.itemView).setChecked(false);
                        }
                    }
                    if ((this.defaultBannedRights.view_messages || this.defaultBannedRights.send_messages) && !this.defaultBannedRights.send_polls) {
                        this.defaultBannedRights.send_polls = true;
                        RecyclerView.ViewHolder holder3 = this.listView.findViewHolderForAdapterPosition(this.sendPollsRow);
                        if (holder3 != null) {
                            ((TextCheckCell2) holder3.itemView).setChecked(false);
                        }
                    }
                    if ((this.defaultBannedRights.view_messages || this.defaultBannedRights.send_messages) && !this.defaultBannedRights.send_stickers) {
                        TLRPC.TL_chatBannedRights tL_chatBannedRights2 = this.defaultBannedRights;
                        tL_chatBannedRights2.send_inline = true;
                        tL_chatBannedRights2.send_gifs = true;
                        tL_chatBannedRights2.send_games = true;
                        tL_chatBannedRights2.send_stickers = true;
                        RecyclerView.ViewHolder holder4 = this.listView.findViewHolderForAdapterPosition(this.sendStickersRow);
                        if (holder4 != null) {
                            ((TextCheckCell2) holder4.itemView).setChecked(false);
                        }
                    }
                    if ((this.defaultBannedRights.view_messages || this.defaultBannedRights.send_messages) && !this.defaultBannedRights.embed_links) {
                        this.defaultBannedRights.embed_links = true;
                        RecyclerView.ViewHolder holder5 = this.listView.findViewHolderForAdapterPosition(this.embedLinksRow);
                        if (holder5 != null) {
                            ((TextCheckCell2) holder5.itemView).setChecked(false);
                            return;
                        }
                        return;
                    }
                    return;
                }
                if ((!this.defaultBannedRights.embed_links || !this.defaultBannedRights.send_inline || !this.defaultBannedRights.send_media || !this.defaultBannedRights.send_polls) && this.defaultBannedRights.send_messages) {
                    this.defaultBannedRights.send_messages = false;
                    RecyclerView.ViewHolder holder6 = this.listView.findViewHolderForAdapterPosition(this.sendMessagesRow);
                    if (holder6 != null) {
                        ((TextCheckCell2) holder6.itemView).setChecked(true);
                        return;
                    }
                    return;
                }
                return;
            }
        }
        TLRPC.TL_chatBannedRights bannedRights2 = null;
        TLRPC.TL_chatAdminRights adminRights2 = null;
        String rank2 = "";
        int user_id2 = 0;
        boolean canEditAdmin2 = false;
        if (listAdapter) {
            TLObject participant4 = this.listViewAdapter.getItem(position);
            if (participant4 instanceof TLRPC.ChannelParticipant) {
                TLRPC.ChannelParticipant channelParticipant = (TLRPC.ChannelParticipant) participant4;
                user_id2 = channelParticipant.user_id;
                bannedRights2 = channelParticipant.banned_rights;
                adminRights2 = channelParticipant.admin_rights;
                rank2 = channelParticipant.rank;
                canEditAdmin2 = ChatObject.canAddAdmins(this.currentChat) && !(participant4 instanceof TLRPC.TL_channelParticipantCreator) && (adminRights2 == null || !adminRights2.add_admins);
                if (participant4 instanceof TLRPC.TL_channelParticipantCreator) {
                    adminRights2 = new TLRPC.TL_chatAdminRights();
                    adminRights2.add_admins = true;
                    adminRights2.pin_messages = true;
                    adminRights2.invite_users = true;
                    adminRights2.ban_users = true;
                    adminRights2.delete_messages = true;
                    adminRights2.edit_messages = true;
                    adminRights2.post_messages = true;
                    adminRights2.change_info = true;
                }
            } else if (participant4 instanceof TLRPC.ChatParticipant) {
                TLRPC.ChatParticipant chatParticipant = (TLRPC.ChatParticipant) participant4;
                int user_id3 = chatParticipant.user_id;
                boolean canEditAdmin3 = this.currentChat.creator;
                if (participant4 instanceof TLRPC.TL_chatParticipantCreator) {
                    adminRights2 = new TLRPC.TL_chatAdminRights();
                    adminRights2.add_admins = true;
                    adminRights2.pin_messages = true;
                    adminRights2.invite_users = true;
                    adminRights2.ban_users = true;
                    adminRights2.delete_messages = true;
                    adminRights2.edit_messages = true;
                    adminRights2.post_messages = true;
                    adminRights2.change_info = true;
                }
                adminRights = adminRights2;
                rank = "";
                canEditAdmin = canEditAdmin3;
                participant2 = participant4;
                bannedRights = null;
                user_id = user_id3;
            }
            adminRights = adminRights2;
            rank = rank2;
            canEditAdmin = canEditAdmin2;
            participant2 = participant4;
            bannedRights = bannedRights2;
            user_id = user_id2;
        } else {
            TLObject object = this.searchListViewAdapter.getItem(position);
            if (object instanceof TLRPC.User) {
                TLRPC.User user = (TLRPC.User) object;
                getMessagesController().putUser(user, false);
                int i3 = user.id;
                user_id2 = i3;
                participant = getAnyParticipant(i3);
            } else if ((object instanceof TLRPC.ChannelParticipant) || (object instanceof TLRPC.ChatParticipant)) {
                participant = object;
            } else {
                participant = null;
            }
            if (participant instanceof TLRPC.ChannelParticipant) {
                if (participant instanceof TLRPC.TL_channelParticipantCreator) {
                    return;
                }
                TLRPC.ChannelParticipant channelParticipant2 = (TLRPC.ChannelParticipant) participant;
                int user_id4 = channelParticipant2.user_id;
                boolean canEditAdmin4 = ChatObject.canAddAdmins(this.currentChat) && (0 == 0 || !adminRights2.add_admins);
                TLRPC.TL_chatBannedRights bannedRights3 = channelParticipant2.banned_rights;
                TLRPC.TL_chatAdminRights adminRights3 = channelParticipant2.admin_rights;
                String rank3 = channelParticipant2.rank;
                bannedRights = bannedRights3;
                rank = rank3;
                canEditAdmin = canEditAdmin4;
                participant2 = participant;
                adminRights = adminRights3;
                user_id = user_id4;
            } else {
                if (participant instanceof TLRPC.ChatParticipant) {
                    if (participant instanceof TLRPC.TL_chatParticipantCreator) {
                        return;
                    }
                    TLRPC.ChatParticipant chatParticipant2 = (TLRPC.ChatParticipant) participant;
                    user_id2 = chatParticipant2.user_id;
                    canEditAdmin2 = this.currentChat.creator;
                    bannedRights2 = null;
                    adminRights2 = null;
                } else if (participant == null) {
                    bannedRights = null;
                    rank = "";
                    canEditAdmin = true;
                    participant2 = participant;
                    adminRights = null;
                    user_id = user_id2;
                }
                bannedRights = bannedRights2;
                rank = "";
                canEditAdmin = canEditAdmin2;
                participant2 = participant;
                adminRights = adminRights2;
                user_id = user_id2;
            }
        }
        if (user_id != 0) {
            int i4 = this.selectType;
            if (i4 != 0) {
                if (i4 == 3 || i4 == 1) {
                    if (this.selectType == 1 || !canEditAdmin) {
                        participant3 = participant2;
                    } else {
                        if ((participant2 instanceof TLRPC.TL_channelParticipantAdmin) || (participant2 instanceof TLRPC.TL_chatParticipantAdmin)) {
                            final TLRPC.User user2 = getMessagesController().getUser(Integer.valueOf(user_id));
                            final TLRPC.TL_chatBannedRights br = bannedRights;
                            final TLRPC.TL_chatAdminRights ar = adminRights;
                            final boolean canEdit = canEditAdmin;
                            final String rankFinal = rank;
                            final TLObject participant5 = participant2;
                            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                            builder.setMessage(LocaleController.formatString("AdminWillBeRemoved", R.string.AdminWillBeRemoved, ContactsController.formatName(user2.first_name, user2.last_name)));
                            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$lcBdKxI0NP3AZC-kwqya5ZM6Icw
                                @Override // android.content.DialogInterface.OnClickListener
                                public final void onClick(DialogInterface dialogInterface, int i5) {
                                    this.f$0.lambda$null$0$ChatUsersActivity(user2, participant5, ar, br, rankFinal, canEdit, dialogInterface, i5);
                                }
                            });
                            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                            showDialog(builder.create());
                            return;
                        }
                        participant3 = participant2;
                    }
                    int i5 = this.selectType == 1 ? 0 : 1;
                    int i6 = this.selectType;
                    openRightsEdit(user_id, participant3, adminRights, bannedRights, rank, canEditAdmin, i5, i6 == 1 || i6 == 3);
                    return;
                }
                removeUser(user_id);
                return;
            }
            final TLObject participant6 = participant2;
            int user_id5 = user_id;
            boolean canEdit2 = false;
            int i7 = this.type;
            if (i7 == 1) {
                canEdit2 = user_id5 != getUserConfig().getClientUserId() && (this.currentChat.creator || canEditAdmin);
            } else if (i7 == 0 || i7 == 3) {
                canEdit2 = ChatObject.canBlockUsers(this.currentChat);
            }
            int i8 = this.type;
            if (i8 == 0) {
                z = true;
            } else {
                if ((i8 == 1 || !this.isChannel) && !(this.type == 2 && this.selectType == 0)) {
                    if (bannedRights != null) {
                        i = 1;
                    } else {
                        bannedRights = new TLRPC.TL_chatBannedRights();
                        i = 1;
                        bannedRights.view_messages = true;
                        bannedRights.send_stickers = true;
                        bannedRights.send_media = true;
                        bannedRights.embed_links = true;
                        bannedRights.send_messages = true;
                        bannedRights.send_games = true;
                        bannedRights.send_inline = true;
                        bannedRights.send_gifs = true;
                        bannedRights.pin_messages = true;
                        bannedRights.send_polls = true;
                        bannedRights.invite_users = true;
                        bannedRights.change_info = true;
                    }
                    ChatRightsEditActivity fragment5 = new ChatRightsEditActivity(user_id5, this.chatId, adminRights, this.defaultBannedRights, bannedRights, rank, this.type == i ? 0 : 1, canEdit2, participant6 == null);
                    fragment5.setDelegate(new ChatRightsEditActivity.ChatRightsEditActivityDelegate() { // from class: im.uwrkaxlmjj.ui.ChatUsersActivity.5
                        @Override // im.uwrkaxlmjj.ui.ChatRightsEditActivity.ChatRightsEditActivityDelegate
                        public void didSetRights(int rights, TLRPC.TL_chatAdminRights rightsAdmin, TLRPC.TL_chatBannedRights rightsBanned, String rank4) {
                            TLObject tLObject = participant6;
                            if (tLObject instanceof TLRPC.ChannelParticipant) {
                                TLRPC.ChannelParticipant channelParticipant3 = (TLRPC.ChannelParticipant) tLObject;
                                channelParticipant3.admin_rights = rightsAdmin;
                                channelParticipant3.banned_rights = rightsBanned;
                                channelParticipant3.rank = rank4;
                                ChatUsersActivity.this.updateParticipantWithRights(channelParticipant3, rightsAdmin, rightsBanned, 0, false);
                            }
                        }

                        @Override // im.uwrkaxlmjj.ui.ChatRightsEditActivity.ChatRightsEditActivityDelegate
                        public void didChangeOwner(TLRPC.User user3) {
                            ChatUsersActivity.this.onOwnerChaged(user3);
                        }
                    });
                    presentFragment(fragment5);
                    return;
                }
                z = true;
            }
            if (this.currentChat instanceof TLRPC.TL_channelForbidden) {
                getNotificationCenter().removeObserver(this, NotificationCenter.closeChats);
                getNotificationCenter().postNotificationName(NotificationCenter.closeChats, new Object[0]);
                AlertDialog dialog = new AlertDialog(getParentActivity(), 0);
                dialog.setTitle(LocaleController.getString("AppName", R.string.AppName));
                dialog.setMessage(LocaleController.getString("DeleteThisGroup", R.string.DeleteThisGroup));
                dialog.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$fGX0KRhdUCD7KdNevYsObH4Uq14
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i9) {
                        this.f$0.lambda$null$1$ChatUsersActivity(dialogInterface, i9);
                    }
                });
                dialog.setCancelable(false);
                dialog.setCanceledOnTouchOutside(false);
                showDialog(dialog);
                return;
            }
            if (user_id5 == getUserConfig().getClientUserId()) {
                return;
            }
            TLRPC.User user3 = getMessagesController().getUser(Integer.valueOf(user_id5));
            if (!user3.self && (chat = this.currentChat) != null && chat.megagroup && (this.currentChat.flags & ConnectionsManager.FileTypeVideo) != 0 && !user3.mutual_contact && !ChatObject.hasAdminRights(this.currentChat)) {
                ToastUtils.show(R.string.ForbidViewUserInfoTips);
                return;
            }
            Bundle args3 = new Bundle();
            args3.putInt("user_id", user_id5);
            TLRPC.Chat chat2 = this.currentChat;
            if (chat2 != null) {
                if (!chat2.megagroup || (33554432 & this.currentChat.flags) == 0) {
                    z = false;
                }
                args3.putBoolean("forbid_add_contact", z);
                args3.putBoolean("has_admin_right", ChatObject.hasAdminRights(this.currentChat));
            }
            args3.putInt("from_type", 2);
            presentFragment(new NewProfileActivity(args3));
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ChatUsersActivity$3, reason: invalid class name */
    class AnonymousClass3 implements ChatUsersActivityDelegate {
        AnonymousClass3() {
        }

        @Override // im.uwrkaxlmjj.ui.ChatUsersActivity.ChatUsersActivityDelegate
        public void didAddParticipantToList(int uid, TLObject participant) {
            if (participant != null && ChatUsersActivity.this.participantsMap.get(uid) == null) {
                ChatUsersActivity.this.participants.add(participant);
                Collections.sort(ChatUsersActivity.this.participants, new Comparator() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$3$31Y3Znqc_EcKsG91B2Fxt2rqVAY
                    @Override // java.util.Comparator
                    public final int compare(Object obj, Object obj2) {
                        return this.f$0.lambda$didAddParticipantToList$0$ChatUsersActivity$3((TLObject) obj, (TLObject) obj2);
                    }
                });
                ChatUsersActivity.this.updateRows();
                if (ChatUsersActivity.this.listViewAdapter != null) {
                    ChatUsersActivity.this.listViewAdapter.notifyDataSetChanged();
                }
            }
        }

        public /* synthetic */ int lambda$didAddParticipantToList$0$ChatUsersActivity$3(TLObject lhs, TLObject rhs) {
            int type1 = ChatUsersActivity.this.getChannelAdminParticipantType(lhs);
            int type2 = ChatUsersActivity.this.getChannelAdminParticipantType(rhs);
            if (type1 > type2) {
                return 1;
            }
            if (type1 < type2) {
                return -1;
            }
            return 0;
        }

        @Override // im.uwrkaxlmjj.ui.ChatUsersActivity.ChatUsersActivityDelegate
        public void didChangeOwner(TLRPC.User user) {
            ChatUsersActivity.this.onOwnerChaged(user);
        }
    }

    public /* synthetic */ void lambda$null$0$ChatUsersActivity(TLRPC.User user, TLObject participant, TLRPC.TL_chatAdminRights ar, TLRPC.TL_chatBannedRights br, String rankFinal, boolean canEdit, DialogInterface dialog, int which) {
        openRightsEdit(user.id, participant, ar, br, rankFinal, canEdit, this.selectType == 1 ? 0 : 1, false);
    }

    public /* synthetic */ void lambda$null$1$ChatUsersActivity(DialogInterface dialog1, int which) {
        MessagesController.getInstance(this.currentAccount).deleteUserFromChat(this.chatId, MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(this.currentAccount).getClientUserId())), this.info, true, false);
        finishFragment();
    }

    public /* synthetic */ boolean lambda$createView$3$ChatUsersActivity(View view, int position) {
        if (getParentActivity() == null) {
            return false;
        }
        RecyclerView.Adapter adapter = this.listView.getAdapter();
        ListAdapter listAdapter = this.listViewAdapter;
        return adapter == listAdapter && createMenuForParticipant(listAdapter.getItem(position), false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onOwnerChaged(TLRPC.User user) {
        TLRPC.User user2;
        SparseArray<TLObject> map;
        ArrayList<TLObject> arrayList;
        boolean foundAny;
        TLRPC.User user3 = user;
        this.undoView.showWithAction(-this.chatId, this.isChannel ? 9 : 10, user3);
        boolean foundAny2 = false;
        this.currentChat.creator = false;
        int a = 0;
        while (a < 3) {
            boolean found = false;
            if (a == 0) {
                map = this.contactsMap;
                arrayList = this.contacts;
            } else if (a == 1) {
                map = this.botsMap;
                arrayList = this.bots;
            } else {
                map = this.participantsMap;
                arrayList = this.participants;
            }
            TLObject object = map.get(user3.id);
            if (object instanceof TLRPC.ChannelParticipant) {
                TLRPC.TL_channelParticipantCreator creator = new TLRPC.TL_channelParticipantCreator();
                creator.user_id = user3.id;
                map.put(user3.id, creator);
                int index = arrayList.indexOf(object);
                if (index >= 0) {
                    arrayList.set(index, creator);
                }
                found = true;
                foundAny2 = true;
            }
            int selfUserId = getUserConfig().getClientUserId();
            TLObject object2 = map.get(selfUserId);
            if (!(object2 instanceof TLRPC.ChannelParticipant)) {
                foundAny = foundAny2;
            } else {
                TLRPC.TL_channelParticipantAdmin admin = new TLRPC.TL_channelParticipantAdmin();
                admin.user_id = selfUserId;
                admin.self = true;
                admin.inviter_id = selfUserId;
                admin.promoted_by = selfUserId;
                admin.date = (int) (System.currentTimeMillis() / 1000);
                admin.admin_rights = new TLRPC.TL_chatAdminRights();
                TLRPC.TL_chatAdminRights tL_chatAdminRights = admin.admin_rights;
                TLRPC.TL_chatAdminRights tL_chatAdminRights2 = admin.admin_rights;
                TLRPC.TL_chatAdminRights tL_chatAdminRights3 = admin.admin_rights;
                TLRPC.TL_chatAdminRights tL_chatAdminRights4 = admin.admin_rights;
                TLRPC.TL_chatAdminRights tL_chatAdminRights5 = admin.admin_rights;
                TLRPC.TL_chatAdminRights tL_chatAdminRights6 = admin.admin_rights;
                foundAny = foundAny2;
                TLRPC.TL_chatAdminRights tL_chatAdminRights7 = admin.admin_rights;
                admin.admin_rights.add_admins = true;
                tL_chatAdminRights7.pin_messages = true;
                tL_chatAdminRights6.invite_users = true;
                tL_chatAdminRights5.ban_users = true;
                tL_chatAdminRights4.delete_messages = true;
                tL_chatAdminRights3.edit_messages = true;
                tL_chatAdminRights2.post_messages = true;
                tL_chatAdminRights.change_info = true;
                map.put(selfUserId, admin);
                int index2 = arrayList.indexOf(object2);
                if (index2 >= 0) {
                    arrayList.set(index2, admin);
                }
                found = true;
            }
            if (found) {
                Collections.sort(arrayList, new Comparator() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$Zisxx4T_6-ML6qdblh-VboBs5s4
                    @Override // java.util.Comparator
                    public final int compare(Object obj, Object obj2) {
                        return this.f$0.lambda$onOwnerChaged$4$ChatUsersActivity((TLObject) obj, (TLObject) obj2);
                    }
                });
            }
            a++;
            user3 = user;
            foundAny2 = foundAny;
        }
        if (foundAny2) {
            user2 = user;
        } else {
            TLRPC.TL_channelParticipantCreator creator2 = new TLRPC.TL_channelParticipantCreator();
            user2 = user;
            creator2.user_id = user2.id;
            this.participantsMap.put(user2.id, creator2);
            this.participants.add(creator2);
            Collections.sort(this.participants, new Comparator() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$lRn9-KvqUEC1RReafSw2ryaqJB8
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return this.f$0.lambda$onOwnerChaged$5$ChatUsersActivity((TLObject) obj, (TLObject) obj2);
                }
            });
            updateRows();
        }
        this.listViewAdapter.notifyDataSetChanged();
        ChatUsersActivityDelegate chatUsersActivityDelegate = this.delegate;
        if (chatUsersActivityDelegate != null) {
            chatUsersActivityDelegate.didChangeOwner(user2);
        }
    }

    public /* synthetic */ int lambda$onOwnerChaged$4$ChatUsersActivity(TLObject lhs, TLObject rhs) {
        int type1 = getChannelAdminParticipantType(lhs);
        int type2 = getChannelAdminParticipantType(rhs);
        if (type1 > type2) {
            return 1;
        }
        if (type1 < type2) {
            return -1;
        }
        return 0;
    }

    public /* synthetic */ int lambda$onOwnerChaged$5$ChatUsersActivity(TLObject lhs, TLObject rhs) {
        int type1 = getChannelAdminParticipantType(lhs);
        int type2 = getChannelAdminParticipantType(rhs);
        if (type1 > type2) {
            return 1;
        }
        if (type1 < type2) {
            return -1;
        }
        return 0;
    }

    private void openRightsEdit2(final int userId, final int date, TLObject participant, TLRPC.TL_chatAdminRights adminRights, TLRPC.TL_chatBannedRights bannedRights, String rank, boolean canEditAdmin, final int type, boolean removeFragment) {
        ChatRightsEditActivity fragment = new ChatRightsEditActivity(userId, this.chatId, adminRights, this.defaultBannedRights, bannedRights, rank, type, true, false);
        fragment.setDelegate(new ChatRightsEditActivity.ChatRightsEditActivityDelegate() { // from class: im.uwrkaxlmjj.ui.ChatUsersActivity.7
            @Override // im.uwrkaxlmjj.ui.ChatRightsEditActivity.ChatRightsEditActivityDelegate
            public void didSetRights(int rights, TLRPC.TL_chatAdminRights rightsAdmin, TLRPC.TL_chatBannedRights rightsBanned, String rank2) {
                TLRPC.ChatParticipant newParticipant;
                TLRPC.ChannelParticipant newPart;
                int i = type;
                if (i == 0) {
                    for (int a = 0; a < ChatUsersActivity.this.participants.size(); a++) {
                        TLObject p = (TLObject) ChatUsersActivity.this.participants.get(a);
                        if (p instanceof TLRPC.ChannelParticipant) {
                            TLRPC.ChannelParticipant p2 = (TLRPC.ChannelParticipant) p;
                            if (p2.user_id == userId) {
                                if (rights == 1) {
                                    newPart = new TLRPC.TL_channelParticipantAdmin();
                                } else {
                                    newPart = new TLRPC.TL_channelParticipant();
                                }
                                newPart.admin_rights = rightsAdmin;
                                newPart.banned_rights = rightsBanned;
                                newPart.inviter_id = ChatUsersActivity.this.getUserConfig().getClientUserId();
                                newPart.user_id = userId;
                                newPart.date = date;
                                newPart.flags |= 4;
                                newPart.rank = rank2;
                                ChatUsersActivity.this.participants.set(a, newPart);
                                return;
                            }
                        } else if (p instanceof TLRPC.ChatParticipant) {
                            TLRPC.ChatParticipant chatParticipant = (TLRPC.ChatParticipant) p;
                            if (rights == 1) {
                                newParticipant = new TLRPC.TL_chatParticipantAdmin();
                            } else {
                                newParticipant = new TLRPC.TL_chatParticipant();
                            }
                            newParticipant.user_id = chatParticipant.user_id;
                            newParticipant.date = chatParticipant.date;
                            newParticipant.inviter_id = chatParticipant.inviter_id;
                            int index = ChatUsersActivity.this.info.participants.participants.indexOf(chatParticipant);
                            if (index >= 0) {
                                ChatUsersActivity.this.info.participants.participants.set(index, newParticipant);
                            }
                            ChatUsersActivity.this.loadChatParticipants(0, ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION);
                        }
                    }
                    return;
                }
                if (i == 1 && rights == 0) {
                    ChatUsersActivity.this.removeParticipants(userId);
                }
            }

            @Override // im.uwrkaxlmjj.ui.ChatRightsEditActivity.ChatRightsEditActivityDelegate
            public void didChangeOwner(TLRPC.User user) {
                ChatUsersActivity.this.onOwnerChaged(user);
            }
        });
        presentFragment(fragment);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openRightsEdit(int user_id, final TLObject participant, TLRPC.TL_chatAdminRights adminRights, TLRPC.TL_chatBannedRights bannedRights, String rank, boolean canEditAdmin, int type, final boolean removeFragment) {
        ChatRightsEditActivity fragment = new ChatRightsEditActivity(user_id, this.chatId, adminRights, this.defaultBannedRights, bannedRights, rank, type, canEditAdmin, participant == null);
        fragment.setDelegate(new ChatRightsEditActivity.ChatRightsEditActivityDelegate() { // from class: im.uwrkaxlmjj.ui.ChatUsersActivity.8
            @Override // im.uwrkaxlmjj.ui.ChatRightsEditActivity.ChatRightsEditActivityDelegate
            public void didSetRights(int rights, TLRPC.TL_chatAdminRights rightsAdmin, TLRPC.TL_chatBannedRights rightsBanned, String rank2) {
                TLObject tLObject = participant;
                if (tLObject instanceof TLRPC.ChannelParticipant) {
                    TLRPC.ChannelParticipant channelParticipant = (TLRPC.ChannelParticipant) tLObject;
                    channelParticipant.admin_rights = rightsAdmin;
                    channelParticipant.banned_rights = rightsBanned;
                    channelParticipant.rank = rank2;
                }
                if (removeFragment) {
                    ChatUsersActivity.this.removeSelfFromStack();
                }
            }

            @Override // im.uwrkaxlmjj.ui.ChatRightsEditActivity.ChatRightsEditActivityDelegate
            public void didChangeOwner(TLRPC.User user) {
                ChatUsersActivity.this.onOwnerChaged(user);
            }
        });
        presentFragment(fragment, removeFragment);
    }

    private void removeUser(int userId) {
        if (!ChatObject.isChannel(this.currentChat)) {
            return;
        }
        TLRPC.User user = getMessagesController().getUser(Integer.valueOf(userId));
        getMessagesController().deleteUserFromChat(this.chatId, user, null);
        finishFragment();
    }

    private TLObject getAnyParticipant(int userId) {
        SparseArray<TLObject> map;
        for (int a = 0; a < 3; a++) {
            if (a == 0) {
                map = this.contactsMap;
            } else if (a == 1) {
                map = this.botsMap;
            } else {
                map = this.participantsMap;
            }
            TLObject p = map.get(userId);
            if (p != null) {
                return p;
            }
        }
        return null;
    }

    private void removeParticipants(TLObject object) {
        if (object instanceof TLRPC.ChatParticipant) {
            TLRPC.ChatParticipant chatParticipant = (TLRPC.ChatParticipant) object;
            removeParticipants(chatParticipant.user_id);
        } else if (object instanceof TLRPC.ChannelParticipant) {
            TLRPC.ChannelParticipant channelParticipant = (TLRPC.ChannelParticipant) object;
            removeParticipants(channelParticipant.user_id);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void removeParticipants(int userId) {
        SparseArray<TLObject> map;
        ArrayList<TLObject> arrayList;
        boolean updated = false;
        for (int a = 0; a < 3; a++) {
            if (a == 0) {
                map = this.contactsMap;
                arrayList = this.contacts;
            } else if (a == 1) {
                map = this.botsMap;
                arrayList = this.bots;
            } else {
                map = this.participantsMap;
                arrayList = this.participants;
            }
            TLObject p = map.get(userId);
            if (p != null) {
                map.remove(userId);
                arrayList.remove(p);
                updated = true;
            }
        }
        if (updated) {
            updateRows();
            this.listViewAdapter.notifyDataSetChanged();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateParticipantWithRights(TLRPC.ChannelParticipant channelParticipant, TLRPC.TL_chatAdminRights rightsAdmin, TLRPC.TL_chatBannedRights rightsBanned, int user_id, boolean withDelegate) {
        SparseArray<TLObject> map;
        ChatUsersActivityDelegate chatUsersActivityDelegate;
        boolean delegateCalled = false;
        for (int a = 0; a < 3; a++) {
            if (a == 0) {
                map = this.contactsMap;
            } else if (a == 1) {
                map = this.botsMap;
            } else {
                map = this.participantsMap;
            }
            TLObject p = map.get(channelParticipant.user_id);
            if (p instanceof TLRPC.ChannelParticipant) {
                channelParticipant = (TLRPC.ChannelParticipant) p;
                channelParticipant.admin_rights = rightsAdmin;
                channelParticipant.banned_rights = rightsBanned;
                if (withDelegate) {
                    channelParticipant.promoted_by = getUserConfig().getClientUserId();
                }
            }
            if (withDelegate && p != null && !delegateCalled && (chatUsersActivityDelegate = this.delegate) != null) {
                delegateCalled = true;
                chatUsersActivityDelegate.didAddParticipantToList(user_id, p);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:128:0x02d2  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean createMenuForParticipant(final im.uwrkaxlmjj.tgnet.TLObject r32, boolean r33) {
        /*
            Method dump skipped, instruction units count: 826
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatUsersActivity.createMenuForParticipant(im.uwrkaxlmjj.tgnet.TLObject, boolean):boolean");
    }

    public /* synthetic */ void lambda$createMenuForParticipant$7$ChatUsersActivity(final ArrayList actions, TLRPC.User user, final int userId, final boolean canEditAdmin, final TLObject participant, final int date, final TLRPC.TL_chatAdminRights adminRights, final TLRPC.TL_chatBannedRights bannedRights, final String rank, DialogInterface dialogInterface, final int i) {
        if (((Integer) actions.get(i)).intValue() == 2) {
            getMessagesController().deleteUserFromChat(this.chatId, user, null);
            removeParticipants(userId);
            if (this.searchItem != null && this.actionBar.isSearchFieldVisible()) {
                this.actionBar.closeSearchField();
                return;
            }
            return;
        }
        if (((Integer) actions.get(i)).intValue() == 1 && canEditAdmin && ((participant instanceof TLRPC.TL_channelParticipantAdmin) || (participant instanceof TLRPC.TL_chatParticipantAdmin))) {
            AlertDialog.Builder builder2 = new AlertDialog.Builder(getParentActivity());
            builder2.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder2.setMessage(LocaleController.formatString("AdminWillBeRemoved", R.string.AdminWillBeRemoved, ContactsController.formatName(user.first_name, user.last_name)));
            builder2.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$co66KAkfvvUyBgthBYTKiv4URYw
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface2, int i2) {
                    this.f$0.lambda$null$6$ChatUsersActivity(userId, date, participant, adminRights, bannedRights, rank, canEditAdmin, actions, i, dialogInterface2, i2);
                }
            });
            builder2.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder2.create());
            return;
        }
        openRightsEdit2(userId, date, participant, adminRights, bannedRights, rank, canEditAdmin, ((Integer) actions.get(i)).intValue(), false);
    }

    public /* synthetic */ void lambda$null$6$ChatUsersActivity(int userId, int date, TLObject participant, TLRPC.TL_chatAdminRights adminRights, TLRPC.TL_chatBannedRights bannedRights, String rank, boolean canEditAdmin, ArrayList actions, int i, DialogInterface dialog, int which) {
        openRightsEdit2(userId, date, participant, adminRights, bannedRights, rank, canEditAdmin, ((Integer) actions.get(i)).intValue(), false);
    }

    public /* synthetic */ void lambda$createMenuForParticipant$10$ChatUsersActivity(CharSequence[] items, int userId, TLRPC.TL_chatAdminRights adminRights, String rank, final TLObject participant, TLRPC.TL_chatBannedRights bannedRights, DialogInterface dialogInterface, int i) {
        TLObject tLObject;
        int i2;
        int i3;
        int i4 = this.type;
        if (i4 == 1) {
            if (i == 0 && items.length == 2) {
                ChatRightsEditActivity fragment = new ChatRightsEditActivity(userId, this.chatId, adminRights, null, null, rank, 0, true, false);
                fragment.setDelegate(new ChatRightsEditActivity.ChatRightsEditActivityDelegate() { // from class: im.uwrkaxlmjj.ui.ChatUsersActivity.9
                    @Override // im.uwrkaxlmjj.ui.ChatRightsEditActivity.ChatRightsEditActivityDelegate
                    public void didSetRights(int rights, TLRPC.TL_chatAdminRights rightsAdmin, TLRPC.TL_chatBannedRights rightsBanned, String rank2) {
                        TLObject tLObject2 = participant;
                        if (tLObject2 instanceof TLRPC.ChannelParticipant) {
                            TLRPC.ChannelParticipant channelParticipant = (TLRPC.ChannelParticipant) tLObject2;
                            channelParticipant.admin_rights = rightsAdmin;
                            channelParticipant.banned_rights = rightsBanned;
                            channelParticipant.rank = rank2;
                            ChatUsersActivity.this.updateParticipantWithRights(channelParticipant, rightsAdmin, rightsBanned, 0, false);
                        }
                    }

                    @Override // im.uwrkaxlmjj.ui.ChatRightsEditActivity.ChatRightsEditActivityDelegate
                    public void didChangeOwner(TLRPC.User user) {
                        ChatUsersActivity.this.onOwnerChaged(user);
                    }
                });
                presentFragment(fragment);
                return;
            }
            getMessagesController().setUserAdminRole(this.chatId, getMessagesController().getUser(Integer.valueOf(userId)), new TLRPC.TL_chatAdminRights(), "", !this.isChannel, this, false);
            removeParticipants(userId);
            return;
        }
        if (i4 == 0 || i4 == 3) {
            if (i == 0) {
                int i5 = this.type;
                if (i5 == 3) {
                    ChatRightsEditActivity fragment2 = new ChatRightsEditActivity(userId, this.chatId, null, this.defaultBannedRights, bannedRights, rank, 1, true, false);
                    fragment2.setDelegate(new ChatRightsEditActivity.ChatRightsEditActivityDelegate() { // from class: im.uwrkaxlmjj.ui.ChatUsersActivity.10
                        @Override // im.uwrkaxlmjj.ui.ChatRightsEditActivity.ChatRightsEditActivityDelegate
                        public void didSetRights(int rights, TLRPC.TL_chatAdminRights rightsAdmin, TLRPC.TL_chatBannedRights rightsBanned, String rank2) {
                            TLObject tLObject2 = participant;
                            if (tLObject2 instanceof TLRPC.ChannelParticipant) {
                                TLRPC.ChannelParticipant channelParticipant = (TLRPC.ChannelParticipant) tLObject2;
                                channelParticipant.admin_rights = rightsAdmin;
                                channelParticipant.banned_rights = rightsBanned;
                                channelParticipant.rank = rank2;
                                ChatUsersActivity.this.updateParticipantWithRights(channelParticipant, rightsAdmin, rightsBanned, 0, false);
                            }
                        }

                        @Override // im.uwrkaxlmjj.ui.ChatRightsEditActivity.ChatRightsEditActivityDelegate
                        public void didChangeOwner(TLRPC.User user) {
                            ChatUsersActivity.this.onOwnerChaged(user);
                        }
                    });
                    presentFragment(fragment2);
                    i2 = i;
                    tLObject = participant;
                    i3 = 1;
                } else if (i5 != 0) {
                    i2 = i;
                    tLObject = participant;
                    i3 = 1;
                } else {
                    TLRPC.User user = getMessagesController().getUser(Integer.valueOf(userId));
                    i3 = 1;
                    i2 = i;
                    tLObject = participant;
                    getMessagesController().addUserToChat(this.chatId, user, null, 0, null, this, null);
                }
            } else {
                tLObject = participant;
                i2 = i;
                i3 = 1;
                if (i2 == 1) {
                    TLRPC.TL_channels_editBanned req = new TLRPC.TL_channels_editBanned();
                    req.user_id = getMessagesController().getInputUser(userId);
                    req.channel = getMessagesController().getInputChannel(this.chatId);
                    req.banned_rights = new TLRPC.TL_chatBannedRights();
                    getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$Rw4Y1TUThz6Zf71KXeGKA8UYbYg
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject2, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$null$9$ChatUsersActivity(tLObject2, tL_error);
                        }
                    });
                    if (this.searchItem != null && this.actionBar.isSearchFieldVisible()) {
                        this.actionBar.closeSearchField();
                    }
                }
            }
            if ((i2 == 0 && this.type == 0) || i2 == i3) {
                removeParticipants(tLObject);
                return;
            }
            return;
        }
        if (i == 0) {
            getMessagesController().deleteUserFromChat(this.chatId, getMessagesController().getUser(Integer.valueOf(userId)), null);
        }
    }

    public /* synthetic */ void lambda$null$9$ChatUsersActivity(TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            final TLRPC.Updates updates = (TLRPC.Updates) response;
            getMessagesController().processUpdates(updates, false);
            if (!updates.chats.isEmpty()) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$TvliPSD679ZoPZuUOL3TxLvHa4c
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$8$ChatUsersActivity(updates);
                    }
                }, 1000L);
            }
        }
    }

    public /* synthetic */ void lambda$null$8$ChatUsersActivity(TLRPC.Updates updates) {
        TLRPC.Chat chat = updates.chats.get(0);
        getMessagesController().loadFullChat(chat.id, 0, true);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.chatInfoDidLoad) {
            TLRPC.ChatFull chatFull = (TLRPC.ChatFull) args[0];
            boolean byChannelUsers = ((Boolean) args[2]).booleanValue();
            if (chatFull.id == this.chatId) {
                if (!byChannelUsers || !ChatObject.isChannel(this.currentChat)) {
                    boolean hadInfo = this.info != null;
                    this.info = chatFull;
                    if (!hadInfo) {
                        int currentSlowmode = getCurrentSlowmode();
                        this.initialSlowmode = currentSlowmode;
                        this.selectedSlowmode = currentSlowmode;
                    }
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$79kzuJscl3iitYJnyL2rxm_fHGU
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$didReceivedNotification$11$ChatUsersActivity();
                        }
                    });
                }
            }
        }
    }

    public /* synthetic */ void lambda$didReceivedNotification$11$ChatUsersActivity() {
        loadChatParticipants(0, ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        return checkDiscard();
    }

    public void setDelegate(ChatUsersActivityDelegate chatUsersActivityDelegate) {
        this.delegate = chatUsersActivityDelegate;
    }

    private int getCurrentSlowmode() {
        TLRPC.ChatFull chatFull = this.info;
        if (chatFull != null) {
            if (chatFull.slowmode_seconds == 10) {
                return 1;
            }
            if (this.info.slowmode_seconds == 30) {
                return 2;
            }
            if (this.info.slowmode_seconds == 60) {
                return 3;
            }
            if (this.info.slowmode_seconds == 300) {
                return 4;
            }
            if (this.info.slowmode_seconds == 900) {
                return 5;
            }
            if (this.info.slowmode_seconds == 3600) {
                return 6;
            }
            return 0;
        }
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getSecondsForIndex(int index) {
        if (index == 1) {
            return 10;
        }
        if (index == 2) {
            return 30;
        }
        if (index == 3) {
            return 60;
        }
        if (index == 4) {
            return 300;
        }
        if (index == 5) {
            return 900;
        }
        if (index == 6) {
            return 3600;
        }
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean checkDiscard() {
        String newBannedRights = ChatObject.getBannedRightsString(this.defaultBannedRights);
        if (!newBannedRights.equals(this.initialBannedRights) || this.initialSlowmode != this.selectedSlowmode) {
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setTitle(LocaleController.getString("UserRestrictionsApplyChanges", R.string.UserRestrictionsApplyChanges));
            if (this.isChannel) {
                builder.setMessage(LocaleController.getString("ChannelSettingsChangedAlert", R.string.ChannelSettingsChangedAlert));
            } else {
                builder.setMessage(LocaleController.getString("GroupSettingsChangedAlert", R.string.GroupSettingsChangedAlert));
            }
            builder.setPositiveButton(LocaleController.getString("ApplyTheme", R.string.ApplyTheme), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$kQmuSxBPZL24Za00cssI16-iKaA
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$checkDiscard$12$ChatUsersActivity(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("PassportDiscard", R.string.PassportDiscard), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$9dqBxKtdfW_sAyj5hJLWKOkebVQ
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$checkDiscard$13$ChatUsersActivity(dialogInterface, i);
                }
            });
            showDialog(builder.create());
            return false;
        }
        return true;
    }

    public /* synthetic */ void lambda$checkDiscard$12$ChatUsersActivity(DialogInterface dialogInterface, int i) {
        processDone();
    }

    public /* synthetic */ void lambda$checkDiscard$13$ChatUsersActivity(DialogInterface dialog, int which) {
        finishFragment();
    }

    public boolean hasSelectType() {
        return this.selectType != 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String formatUserPermissions(TLRPC.TL_chatBannedRights rights) {
        if (rights == null) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        if (rights.view_messages && this.defaultBannedRights.view_messages != rights.view_messages) {
            builder.append(LocaleController.getString("UserRestrictionsNoRead", R.string.UserRestrictionsNoRead));
        }
        if (rights.send_messages && this.defaultBannedRights.send_messages != rights.send_messages) {
            if (builder.length() != 0) {
                builder.append(", ");
            }
            builder.append(LocaleController.getString("UserRestrictionsNoSend", R.string.UserRestrictionsNoSend));
        }
        if (rights.send_media && this.defaultBannedRights.send_media != rights.send_media) {
            if (builder.length() != 0) {
                builder.append(", ");
            }
            builder.append(LocaleController.getString("UserRestrictionsNoSendMedia", R.string.UserRestrictionsNoSendMedia));
        }
        if (rights.send_stickers && this.defaultBannedRights.send_stickers != rights.send_stickers) {
            if (builder.length() != 0) {
                builder.append(", ");
            }
            builder.append(LocaleController.getString("UserRestrictionsNoSendStickers", R.string.UserRestrictionsNoSendStickers));
        }
        if (rights.send_polls && this.defaultBannedRights.send_polls != rights.send_polls) {
            if (builder.length() != 0) {
                builder.append(", ");
            }
            builder.append(LocaleController.getString("UserRestrictionsNoSendPolls", R.string.UserRestrictionsNoSendPolls));
        }
        if (rights.embed_links && this.defaultBannedRights.embed_links != rights.embed_links) {
            if (builder.length() != 0) {
                builder.append(", ");
            }
            builder.append(LocaleController.getString("UserRestrictionsNoEmbedLinks", R.string.UserRestrictionsNoEmbedLinks));
        }
        if (rights.invite_users && this.defaultBannedRights.invite_users != rights.invite_users) {
            if (builder.length() != 0) {
                builder.append(", ");
            }
            builder.append(LocaleController.getString("UserRestrictionsNoInviteUsers", R.string.UserRestrictionsNoInviteUsers));
        }
        if (rights.pin_messages && this.defaultBannedRights.pin_messages != rights.pin_messages) {
            if (builder.length() != 0) {
                builder.append(", ");
            }
            builder.append(LocaleController.getString("UserRestrictionsNoPinMessages", R.string.UserRestrictionsNoPinMessages));
        }
        if (rights.change_info && this.defaultBannedRights.change_info != rights.change_info) {
            if (builder.length() != 0) {
                builder.append(", ");
            }
            builder.append(LocaleController.getString("UserRestrictionsNoChangeInfo", R.string.UserRestrictionsNoChangeInfo));
        }
        if (builder.length() != 0) {
            builder.replace(0, 1, builder.substring(0, 1).toUpperCase());
            builder.append('.');
        }
        return builder.toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processDone() {
        if (this.type != 3) {
            return;
        }
        if (!ChatObject.isChannel(this.currentChat) && this.selectedSlowmode != this.initialSlowmode && this.info != null) {
            MessagesController.getInstance(this.currentAccount).convertToMegaGroup(getParentActivity(), this.chatId, this, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$Ewga-wRWEIbicSHaUc2HvCNX7ao
                @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
                public final void run(int i) {
                    this.f$0.lambda$processDone$14$ChatUsersActivity(i);
                }
            });
            return;
        }
        String newBannedRights = ChatObject.getBannedRightsString(this.defaultBannedRights);
        if (!newBannedRights.equals(this.initialBannedRights)) {
            getMessagesController().setDefaultBannedRole(this.chatId, this.defaultBannedRights, ChatObject.isChannel(this.currentChat), this);
            TLRPC.Chat chat = getMessagesController().getChat(Integer.valueOf(this.chatId));
            if (chat != null) {
                chat.default_banned_rights = this.defaultBannedRights;
            }
        }
        if (this.selectedSlowmode != this.initialSlowmode && this.info != null) {
            getMessagesController().setChannelSlowMode(this.chatId, this.info.slowmode_seconds);
        }
        finishFragment();
    }

    public /* synthetic */ void lambda$processDone$14$ChatUsersActivity(int param) {
        this.chatId = param;
        this.currentChat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(param));
        processDone();
    }

    public void setInfo(TLRPC.ChatFull chatFull) {
        this.info = chatFull;
        if (chatFull != null) {
            int currentSlowmode = getCurrentSlowmode();
            this.initialSlowmode = currentSlowmode;
            this.selectedSlowmode = currentSlowmode;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getChannelAdminParticipantType(TLObject participant) {
        if ((participant instanceof TLRPC.TL_channelParticipantCreator) || (participant instanceof TLRPC.TL_channelParticipantSelf)) {
            return 0;
        }
        if ((participant instanceof TLRPC.TL_channelParticipantAdmin) || (participant instanceof TLRPC.TL_channelParticipant)) {
            return 1;
        }
        return 2;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void loadChatParticipants(int offset, int count) {
        if (this.loadingUsers) {
            return;
        }
        this.contactsEndReached = false;
        this.botsEndReached = false;
        loadChatParticipants(offset, count, true);
    }

    private void loadChatParticipants(int offset, int count, boolean reset) {
        TLRPC.Chat chat;
        if (!ChatObject.isChannel(this.currentChat)) {
            this.loadingUsers = false;
            this.participants.clear();
            this.bots.clear();
            this.contacts.clear();
            this.participantsMap.clear();
            this.contactsMap.clear();
            this.botsMap.clear();
            int i = this.type;
            if (i == 1) {
                TLRPC.ChatFull chatFull = this.info;
                if (chatFull != null) {
                    int size = chatFull.participants.participants.size();
                    for (int a = 0; a < size; a++) {
                        TLRPC.ChatParticipant participant = this.info.participants.participants.get(a);
                        if ((participant instanceof TLRPC.TL_chatParticipantCreator) || (participant instanceof TLRPC.TL_chatParticipantAdmin)) {
                            this.participants.add(participant);
                        }
                        this.participantsMap.put(participant.user_id, participant);
                    }
                }
            } else if (i == 2 && this.info != null) {
                int selfUserId = getUserConfig().clientUserId;
                int size2 = this.info.participants.participants.size();
                for (int a2 = 0; a2 < size2; a2++) {
                    TLRPC.ChatParticipant participant2 = this.info.participants.participants.get(a2);
                    if (this.selectType == 0 || participant2.user_id != selfUserId) {
                        if (this.selectType == 1) {
                            if (getContactsController().isContact(participant2.user_id)) {
                                this.contacts.add(participant2);
                                this.contactsMap.put(participant2.user_id, participant2);
                            } else {
                                this.participants.add(participant2);
                                this.participantsMap.put(participant2.user_id, participant2);
                            }
                        } else if (getContactsController().isContact(participant2.user_id)) {
                            this.contacts.add(participant2);
                            this.contactsMap.put(participant2.user_id, participant2);
                        } else {
                            TLRPC.User user = getMessagesController().getUser(Integer.valueOf(participant2.user_id));
                            if (user != null && user.bot) {
                                this.bots.add(participant2);
                                this.botsMap.put(participant2.user_id, participant2);
                            } else {
                                this.participants.add(participant2);
                                this.participantsMap.put(participant2.user_id, participant2);
                            }
                        }
                    }
                }
            }
            ListAdapter listAdapter = this.listViewAdapter;
            if (listAdapter != null) {
                listAdapter.notifyDataSetChanged();
            }
            updateRows();
            ListAdapter listAdapter2 = this.listViewAdapter;
            if (listAdapter2 != null) {
                listAdapter2.notifyDataSetChanged();
                return;
            }
            return;
        }
        this.loadingUsers = true;
        EmptyTextProgressView emptyTextProgressView = this.emptyView;
        if (emptyTextProgressView != null && !this.firstLoaded) {
            emptyTextProgressView.showProgress();
        }
        ListAdapter listAdapter3 = this.listViewAdapter;
        if (listAdapter3 != null) {
            listAdapter3.notifyDataSetChanged();
        }
        final TLRPC.TL_channels_getParticipants req = new TLRPC.TL_channels_getParticipants();
        req.channel = getMessagesController().getInputChannel(this.chatId);
        int i2 = this.type;
        if (i2 == 0) {
            req.filter = new TLRPC.TL_channelParticipantsKicked();
        } else if (i2 == 1) {
            req.filter = new TLRPC.TL_channelParticipantsAdmins();
        } else if (i2 == 2) {
            TLRPC.ChatFull chatFull2 = this.info;
            if (chatFull2 != null && chatFull2.participants_count <= 200 && (chat = this.currentChat) != null && chat.megagroup) {
                req.filter = new TLRPC.TL_channelParticipantsRecent();
            } else if (this.selectType == 1) {
                if (!this.contactsEndReached) {
                    this.delayResults = 2;
                    req.filter = new TLRPC.TL_channelParticipantsContacts();
                    this.contactsEndReached = true;
                    loadChatParticipants(0, ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, false);
                } else {
                    req.filter = new TLRPC.TL_channelParticipantsRecent();
                }
            } else if (!this.contactsEndReached) {
                this.delayResults = 3;
                req.filter = new TLRPC.TL_channelParticipantsContacts();
                this.contactsEndReached = true;
                loadChatParticipants(0, ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, false);
            } else if (!this.botsEndReached) {
                req.filter = new TLRPC.TL_channelParticipantsBots();
                this.botsEndReached = true;
                loadChatParticipants(0, ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, false);
            } else {
                req.filter = new TLRPC.TL_channelParticipantsRecent();
            }
        } else if (i2 == 3) {
            req.filter = new TLRPC.TL_channelParticipantsBanned();
        }
        req.filter.q = "";
        req.offset = offset;
        req.limit = count;
        int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$JRmiX1J5ggpDqZMu5cyQepzkl8A
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadChatParticipants$18$ChatUsersActivity(req, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(reqId, this.classGuid);
    }

    public /* synthetic */ void lambda$loadChatParticipants$18$ChatUsersActivity(final TLRPC.TL_channels_getParticipants req, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$P3sQR3eR2V6exMX_H5YT81Gb3uk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$17$ChatUsersActivity(error, response, req);
            }
        });
    }

    public /* synthetic */ void lambda$null$17$ChatUsersActivity(TLRPC.TL_error error, TLObject response, TLRPC.TL_channels_getParticipants req) {
        ArrayList<TLObject> objects;
        SparseArray<TLObject> map;
        EmptyTextProgressView emptyTextProgressView;
        if (error == null) {
            TLRPC.TL_channels_channelParticipants res = (TLRPC.TL_channels_channelParticipants) response;
            if (this.type == 1) {
                getMessagesController().processLoadedAdminsResponse(this.chatId, (TLRPC.TL_channels_channelParticipants) response);
            }
            getMessagesController().putUsers(res.users, false);
            int selfId = getUserConfig().getClientUserId();
            if (this.selectType != 0) {
                int a = 0;
                while (true) {
                    if (a >= res.participants.size()) {
                        break;
                    }
                    if (res.participants.get(a).user_id != selfId) {
                        a++;
                    } else {
                        res.participants.remove(a);
                        break;
                    }
                }
            }
            int a2 = this.type;
            if (a2 == 2) {
                this.delayResults--;
                if (req.filter instanceof TLRPC.TL_channelParticipantsContacts) {
                    objects = this.contacts;
                    map = this.contactsMap;
                } else if (req.filter instanceof TLRPC.TL_channelParticipantsBots) {
                    objects = this.bots;
                    map = this.botsMap;
                } else {
                    objects = this.participants;
                    map = this.participantsMap;
                }
                if (this.delayResults <= 0 && (emptyTextProgressView = this.emptyView) != null) {
                    emptyTextProgressView.showTextView();
                }
            } else {
                objects = this.participants;
                map = this.participantsMap;
                this.participantsMap.clear();
                EmptyTextProgressView emptyTextProgressView2 = this.emptyView;
                if (emptyTextProgressView2 != null) {
                    emptyTextProgressView2.showTextView();
                }
            }
            objects.clear();
            objects.addAll(res.participants);
            int size = res.participants.size();
            for (int a3 = 0; a3 < size; a3++) {
                TLRPC.ChannelParticipant participant = res.participants.get(a3);
                map.put(participant.user_id, participant);
            }
            int a4 = this.type;
            if (a4 == 2) {
                int a5 = 0;
                int N = this.participants.size();
                while (a5 < N) {
                    TLRPC.ChannelParticipant participant2 = (TLRPC.ChannelParticipant) this.participants.get(a5);
                    if (this.contactsMap.get(participant2.user_id) != null || this.botsMap.get(participant2.user_id) != null) {
                        this.participants.remove(a5);
                        this.participantsMap.remove(participant2.user_id);
                        a5--;
                        N--;
                    }
                    a5++;
                }
            }
            try {
                int a6 = this.type;
                if ((a6 == 0 || this.type == 3 || this.type == 2) && this.currentChat != null && this.currentChat.megagroup && (this.info instanceof TLRPC.TL_channelFull) && this.info.participants_count <= 200) {
                    final int currentTime = getConnectionsManager().getCurrentTime();
                    Collections.sort(objects, new Comparator() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$z2h-kp6fuoBQqxHx9NoxljTb70w
                        @Override // java.util.Comparator
                        public final int compare(Object obj, Object obj2) {
                            return this.f$0.lambda$null$15$ChatUsersActivity(currentTime, (TLObject) obj, (TLObject) obj2);
                        }
                    });
                } else if (this.type == 1) {
                    Collections.sort(this.participants, new Comparator() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$ukWRF6gzzUMG3bh2MhNFNAL8T5A
                        @Override // java.util.Comparator
                        public final int compare(Object obj, Object obj2) {
                            return this.f$0.lambda$null$16$ChatUsersActivity((TLObject) obj, (TLObject) obj2);
                        }
                    });
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        if (this.type != 2 || this.delayResults <= 0) {
            this.loadingUsers = false;
            this.firstLoaded = true;
        }
        updateRows();
        ListAdapter listAdapter = this.listViewAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    public /* synthetic */ int lambda$null$15$ChatUsersActivity(int currentTime, TLObject lhs, TLObject rhs) {
        TLRPC.ChannelParticipant p1 = (TLRPC.ChannelParticipant) lhs;
        TLRPC.ChannelParticipant p2 = (TLRPC.ChannelParticipant) rhs;
        TLRPC.User user1 = getMessagesController().getUser(Integer.valueOf(p1.user_id));
        TLRPC.User user2 = getMessagesController().getUser(Integer.valueOf(p2.user_id));
        int status1 = 0;
        int status2 = 0;
        if (user1 != null && user1.status != null) {
            status1 = user1.self ? currentTime + 50000 : user1.status.expires;
        }
        if (user2 != null && user2.status != null) {
            status2 = user2.self ? currentTime + 50000 : user2.status.expires;
        }
        if (status1 > 0 && status2 > 0) {
            if (status1 > status2) {
                return 1;
            }
            return status1 < status2 ? -1 : 0;
        }
        if (status1 < 0 && status2 < 0) {
            if (status1 > status2) {
                return 1;
            }
            return status1 < status2 ? -1 : 0;
        }
        if ((status1 >= 0 || status2 <= 0) && (status1 != 0 || status2 == 0)) {
            return ((status2 >= 0 || status1 <= 0) && (status2 != 0 || status1 == 0)) ? 0 : 1;
        }
        return -1;
    }

    public /* synthetic */ int lambda$null$16$ChatUsersActivity(TLObject lhs, TLObject rhs) {
        int type1 = getChannelAdminParticipantType(lhs);
        int type2 = getChannelAdminParticipantType(rhs);
        if (type1 > type2) {
            return 1;
        }
        if (type1 < type2) {
            return -1;
        }
        return 0;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        AndroidUtilities.requestAdjustResize(getParentActivity(), this.classGuid);
        ListAdapter listAdapter = this.listViewAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        UndoView undoView = this.undoView;
        if (undoView != null) {
            undoView.hide(true, 0);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onBecomeFullyHidden() {
        UndoView undoView = this.undoView;
        if (undoView != null) {
            undoView.hide(true, 0);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        if (isOpen && !backward && this.needOpenSearch) {
            this.searchItem.openSearch(true);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class SearchAdapter extends RecyclerListView.SelectionAdapter {
        private int contactsStartRow;
        private int globalStartRow;
        private int groupStartRow;
        private Context mContext;
        private SearchAdapterHelper searchAdapterHelper;
        private ArrayList<TLObject> searchResult = new ArrayList<>();
        private ArrayList<CharSequence> searchResultNames = new ArrayList<>();
        private Runnable searchRunnable;
        private int totalCount;

        public SearchAdapter(Context context) {
            this.mContext = context;
            SearchAdapterHelper searchAdapterHelper = new SearchAdapterHelper(true);
            this.searchAdapterHelper = searchAdapterHelper;
            searchAdapterHelper.setDelegate(new SearchAdapterHelper.SearchAdapterHelperDelegate() { // from class: im.uwrkaxlmjj.ui.ChatUsersActivity.SearchAdapter.1
                @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
                public /* synthetic */ SparseArray<TLRPC.User> getExcludeUsers() {
                    return SearchAdapterHelper.SearchAdapterHelperDelegate.CC.$default$getExcludeUsers(this);
                }

                @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
                public void onDataSetChanged() {
                    SearchAdapter.this.notifyDataSetChanged();
                }

                @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
                public void onSetHashtags(ArrayList<SearchAdapterHelper.HashtagObject> arrayList, HashMap<String, SearchAdapterHelper.HashtagObject> hashMap) {
                }
            });
        }

        public void searchDialogs(final String query) {
            if (this.searchRunnable != null) {
                Utilities.searchQueue.cancelRunnable(this.searchRunnable);
                this.searchRunnable = null;
            }
            if (TextUtils.isEmpty(query)) {
                this.searchResult.clear();
                this.searchResultNames.clear();
                this.searchAdapterHelper.mergeResults(null);
                this.searchAdapterHelper.queryServerSearch(null, ChatUsersActivity.this.type != 0, false, true, false, ChatObject.isChannel(ChatUsersActivity.this.currentChat) ? ChatUsersActivity.this.chatId : 0, false, ChatUsersActivity.this.type);
                notifyDataSetChanged();
                return;
            }
            DispatchQueue dispatchQueue = Utilities.searchQueue;
            Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$SearchAdapter$zFb5nw9f1lFbjanGJAtjshqYzRU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$searchDialogs$0$ChatUsersActivity$SearchAdapter(query);
                }
            };
            this.searchRunnable = runnable;
            dispatchQueue.postRunnable(runnable, 300L);
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* JADX INFO: renamed from: processSearch, reason: merged with bridge method [inline-methods] */
        public void lambda$searchDialogs$0$ChatUsersActivity$SearchAdapter(final String query) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$SearchAdapter$rsapt-f0EPt_mUIh-48EfxV9SCI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$processSearch$2$ChatUsersActivity$SearchAdapter(query);
                }
            });
        }

        public /* synthetic */ void lambda$processSearch$2$ChatUsersActivity$SearchAdapter(final String query) {
            final ArrayList<TLRPC.ChatParticipant> participantsCopy;
            final ArrayList<TLRPC.Contact> contactsCopy = null;
            this.searchRunnable = null;
            if (!ChatUsersActivity.this.isChannel && ChatUsersActivity.this.info != null) {
                participantsCopy = new ArrayList<>(ChatUsersActivity.this.info.participants.participants);
            } else {
                participantsCopy = null;
            }
            if (ChatUsersActivity.this.selectType == 1) {
                contactsCopy = new ArrayList<>(ChatUsersActivity.this.getContactsController().contacts);
            }
            this.searchAdapterHelper.queryServerSearch(query, ChatUsersActivity.this.selectType != 0, false, true, false, ChatObject.isChannel(ChatUsersActivity.this.currentChat) ? ChatUsersActivity.this.chatId : 0, false, ChatUsersActivity.this.type);
            if (participantsCopy != null || contactsCopy != null) {
                Utilities.searchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$SearchAdapter$cvlooCcwdOFEwjJiS9Ci4D7xeS4
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$1$ChatUsersActivity$SearchAdapter(query, participantsCopy, contactsCopy);
                    }
                });
            }
        }

        /* JADX WARN: Removed duplicated region for block: B:51:0x011d A[LOOP:1: B:30:0x00af->B:51:0x011d, LOOP_END] */
        /* JADX WARN: Removed duplicated region for block: B:95:0x00de A[SYNTHETIC] */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public /* synthetic */ void lambda$null$1$ChatUsersActivity$SearchAdapter(java.lang.String r21, java.util.ArrayList r22, java.util.ArrayList r23) {
            /*
                Method dump skipped, instruction units count: 514
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatUsersActivity.SearchAdapter.lambda$null$1$ChatUsersActivity$SearchAdapter(java.lang.String, java.util.ArrayList, java.util.ArrayList):void");
        }

        private void updateSearchResults(final ArrayList<TLObject> users, final ArrayList<CharSequence> names, final ArrayList<TLObject> participants) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$SearchAdapter$qDuxnZi4obdAVHz3EtEgxPt5Has
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$updateSearchResults$3$ChatUsersActivity$SearchAdapter(users, names, participants);
                }
            });
        }

        public /* synthetic */ void lambda$updateSearchResults$3$ChatUsersActivity$SearchAdapter(ArrayList users, ArrayList names, ArrayList participants) {
            this.searchResult = users;
            this.searchResultNames = names;
            this.searchAdapterHelper.mergeResults(users);
            if (!ChatUsersActivity.this.isChannel) {
                ArrayList<TLObject> search = this.searchAdapterHelper.getGroupSearch();
                search.clear();
                search.addAll(participants);
            }
            notifyDataSetChanged();
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() != 1;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int contactsCount = this.searchResult.size();
            int globalCount = this.searchAdapterHelper.getGlobalSearch().size();
            int groupsCount = this.searchAdapterHelper.getGroupSearch().size();
            int count = contactsCount != 0 ? 0 + contactsCount + 1 : 0;
            if (globalCount != 0) {
                count += globalCount + 1;
            }
            if (groupsCount != 0) {
                return count + groupsCount + 1;
            }
            return count;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            this.totalCount = 0;
            int count = this.searchAdapterHelper.getGroupSearch().size();
            if (count != 0) {
                this.groupStartRow = 0;
                this.totalCount += count + 1;
            } else {
                this.groupStartRow = -1;
            }
            int count2 = this.searchResult.size();
            if (count2 != 0) {
                int i = this.totalCount;
                this.contactsStartRow = i;
                this.totalCount = i + count2 + 1;
            } else {
                this.contactsStartRow = -1;
            }
            int count3 = this.searchAdapterHelper.getGlobalSearch().size();
            if (count3 != 0) {
                int i2 = this.totalCount;
                this.globalStartRow = i2;
                this.totalCount = i2 + count3 + 1;
            } else {
                this.globalStartRow = -1;
            }
            super.notifyDataSetChanged();
        }

        public TLObject getItem(int i) {
            int count = this.searchAdapterHelper.getGroupSearch().size();
            if (count != 0) {
                if (count + 1 > i) {
                    if (i == 0) {
                        return null;
                    }
                    return this.searchAdapterHelper.getGroupSearch().get(i - 1);
                }
                i -= count + 1;
            }
            int count2 = this.searchResult.size();
            if (count2 != 0) {
                if (count2 + 1 > i) {
                    if (i == 0) {
                        return null;
                    }
                    return this.searchResult.get(i - 1);
                }
                i -= count2 + 1;
            }
            int count3 = this.searchAdapterHelper.getGlobalSearch().size();
            if (count3 == 0 || count3 + 1 <= i || i == 0) {
                return null;
            }
            return this.searchAdapterHelper.getGlobalSearch().get(i - 1);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new ManageChatUserCell(this.mContext, 2, 2, ChatUsersActivity.this.selectType == 0);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                ((ManageChatUserCell) view).setDelegate(new ManageChatUserCell.ManageChatUserCellDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$SearchAdapter$MM237gfadZ43C2vAdRu9DcvRxlI
                    @Override // im.uwrkaxlmjj.ui.cells.ManageChatUserCell.ManageChatUserCellDelegate
                    public final boolean onOptionsButtonCheck(ManageChatUserCell manageChatUserCell, boolean z) {
                        return this.f$0.lambda$onCreateViewHolder$4$ChatUsersActivity$SearchAdapter(manageChatUserCell, z);
                    }
                });
            } else {
                view = new GraySectionCell(this.mContext);
            }
            return new RecyclerListView.Holder(view);
        }

        public /* synthetic */ boolean lambda$onCreateViewHolder$4$ChatUsersActivity$SearchAdapter(ManageChatUserCell cell, boolean click) {
            if (cell == null || cell.getTag() == null) {
                return false;
            }
            TLObject object = getItem(((Integer) cell.getTag()).intValue());
            if (!(object instanceof TLRPC.ChannelParticipant)) {
                return false;
            }
            TLRPC.ChannelParticipant participant = (TLRPC.ChannelParticipant) getItem(((Integer) cell.getTag()).intValue());
            return ChatUsersActivity.this.createMenuForParticipant(participant, !click);
        }

        /* JADX WARN: Removed duplicated region for block: B:54:0x0135  */
        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void onBindViewHolder(androidx.recyclerview.widget.RecyclerView.ViewHolder r21, int r22) {
            /*
                Method dump skipped, instruction units count: 534
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatUsersActivity.SearchAdapter.onBindViewHolder(androidx.recyclerview.widget.RecyclerView$ViewHolder, int):void");
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewRecycled(RecyclerView.ViewHolder holder) {
            if (holder.itemView instanceof ManageChatUserCell) {
                ((ManageChatUserCell) holder.itemView).recycle();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            if (i == this.globalStartRow || i == this.groupStartRow || i == this.contactsStartRow) {
                return 1;
            }
            return 0;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int type = holder.getItemViewType();
            if (type == 7) {
                return ChatObject.canBlockUsers(ChatUsersActivity.this.currentChat);
            }
            if (type != 0) {
                return type == 0 || type == 2 || type == 6;
            }
            ManageChatUserCell cell = (ManageChatUserCell) holder.itemView;
            TLObject object = cell.getCurrentObject();
            if (object instanceof TLRPC.User) {
                TLRPC.User user = (TLRPC.User) object;
                if (user.self) {
                    return false;
                }
            }
            return true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (!ChatUsersActivity.this.loadingUsers || ChatUsersActivity.this.firstLoaded) {
                return ChatUsersActivity.this.rowCount;
            }
            return 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int i) {
            View manageChatTextCell;
            switch (i) {
                case 0:
                    Context context = this.mContext;
                    int i2 = 6;
                    int i3 = (ChatUsersActivity.this.type == 0 || ChatUsersActivity.this.type == 3) ? 7 : 6;
                    if (ChatUsersActivity.this.type != 0 && ChatUsersActivity.this.type != 3) {
                        i2 = 2;
                    }
                    ManageChatUserCell manageChatUserCell = new ManageChatUserCell(context, i3, i2, ChatUsersActivity.this.selectType == 0);
                    manageChatUserCell.setDelegate(new ManageChatUserCell.ManageChatUserCellDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$ListAdapter$QGq85HAmLdMO99nCy0guLLEY9hU
                        @Override // im.uwrkaxlmjj.ui.cells.ManageChatUserCell.ManageChatUserCellDelegate
                        public final boolean onOptionsButtonCheck(ManageChatUserCell manageChatUserCell2, boolean z) {
                            return this.f$0.lambda$onCreateViewHolder$0$ChatUsersActivity$ListAdapter(manageChatUserCell2, z);
                        }
                    });
                    manageChatTextCell = manageChatUserCell;
                    break;
                case 1:
                    TextInfoPrivacyCell textInfoPrivacyCell = new TextInfoPrivacyCell(this.mContext);
                    textInfoPrivacyCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
                    manageChatTextCell = textInfoPrivacyCell;
                    break;
                case 2:
                    manageChatTextCell = new ManageChatTextCell(this.mContext);
                    break;
                case 3:
                    manageChatTextCell = new ShadowSectionCell(this.mContext);
                    break;
                case 4:
                    FrameLayout frameLayout = new FrameLayout(this.mContext) { // from class: im.uwrkaxlmjj.ui.ChatUsersActivity.ListAdapter.1
                        @Override // android.widget.FrameLayout, android.view.View
                        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                            super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(heightMeasureSpec) - AndroidUtilities.dp(56.0f), 1073741824));
                        }
                    };
                    LinearLayout linearLayout = new LinearLayout(this.mContext);
                    linearLayout.setOrientation(1);
                    frameLayout.addView(linearLayout, LayoutHelper.createFrame(-2.0f, -2.0f, 17, 20.0f, 0.0f, 20.0f, 0.0f));
                    ImageView imageView = new ImageView(this.mContext);
                    imageView.setImageResource(R.drawable.group_ban_empty);
                    imageView.setScaleType(ImageView.ScaleType.CENTER);
                    imageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_emptyListPlaceholder), PorterDuff.Mode.MULTIPLY));
                    linearLayout.addView(imageView, LayoutHelper.createLinear(-2, -2, 1));
                    TextView textView = new TextView(this.mContext);
                    textView.setText(LocaleController.getString("NoBlockedUsers", R.string.NoBlockedUsers));
                    textView.setTextColor(Theme.getColor(Theme.key_emptyListPlaceholder));
                    textView.setTextSize(1, 16.0f);
                    textView.setGravity(1);
                    textView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                    linearLayout.addView(textView, LayoutHelper.createLinear(-2, -2, 1, 0, 10, 0, 0));
                    TextView textView2 = new TextView(this.mContext);
                    if (ChatUsersActivity.this.isChannel) {
                        textView2.setText(LocaleController.getString("NoBlockedChannel2", R.string.NoBlockedChannel2));
                    } else {
                        textView2.setText(LocaleController.getString("NoBlockedGroup2", R.string.NoBlockedGroup2));
                    }
                    textView2.setTextColor(Theme.getColor(Theme.key_emptyListPlaceholder));
                    textView2.setTextSize(1, 15.0f);
                    textView2.setGravity(1);
                    linearLayout.addView(textView2, LayoutHelper.createLinear(-2, -2, 1, 0, 10, 0, 0));
                    frameLayout.setLayoutParams(new RecyclerView.LayoutParams(-1, -1));
                    manageChatTextCell = frameLayout;
                    break;
                case 5:
                    HeaderCell headerCell = new HeaderCell(this.mContext, false, 21, 11, false);
                    headerCell.setHeight(43);
                    manageChatTextCell = headerCell;
                    break;
                case 6:
                    manageChatTextCell = new TextSettingsCell(this.mContext);
                    break;
                case 7:
                    manageChatTextCell = new TextCheckCell2(this.mContext);
                    break;
                case 8:
                    manageChatTextCell = new GraySectionCell(this.mContext);
                    break;
                default:
                    manageChatTextCell = ChatUsersActivity.this.new ChooseView(this.mContext);
                    break;
            }
            return new RecyclerListView.Holder(manageChatTextCell);
        }

        public /* synthetic */ boolean lambda$onCreateViewHolder$0$ChatUsersActivity$ListAdapter(ManageChatUserCell cell, boolean click) {
            TLObject participant = ChatUsersActivity.this.listViewAdapter.getItem(((Integer) cell.getTag()).intValue());
            return ChatUsersActivity.this.createMenuForParticipant(participant, !click);
        }

        /* JADX WARN: Removed duplicated region for block: B:259:0x068b  */
        /* JADX WARN: Removed duplicated region for block: B:260:0x068d  */
        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void onBindViewHolder(androidx.recyclerview.widget.RecyclerView.ViewHolder r19, int r20) {
            /*
                Method dump skipped, instruction units count: 1868
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatUsersActivity.ListAdapter.onBindViewHolder(androidx.recyclerview.widget.RecyclerView$ViewHolder, int):void");
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewRecycled(RecyclerView.ViewHolder holder) {
            if (holder.itemView instanceof ManageChatUserCell) {
                ((ManageChatUserCell) holder.itemView).recycle();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != ChatUsersActivity.this.addNewRow && position != ChatUsersActivity.this.addNew2Row && position != ChatUsersActivity.this.recentActionsRow) {
                if ((position >= ChatUsersActivity.this.participantsStartRow && position < ChatUsersActivity.this.participantsEndRow) || ((position >= ChatUsersActivity.this.botStartRow && position < ChatUsersActivity.this.botEndRow) || (position >= ChatUsersActivity.this.contactsStartRow && position < ChatUsersActivity.this.contactsEndRow))) {
                    return 0;
                }
                if (position != ChatUsersActivity.this.addNewSectionRow && position != ChatUsersActivity.this.participantsDividerRow && position != ChatUsersActivity.this.participantsDivider2Row) {
                    if (position != ChatUsersActivity.this.restricted1SectionRow && position != ChatUsersActivity.this.permissionsSectionRow && position != ChatUsersActivity.this.slowmodeRow) {
                        if (position != ChatUsersActivity.this.participantsInfoRow && position != ChatUsersActivity.this.slowmodeInfoRow) {
                            if (position != ChatUsersActivity.this.blockedEmptyRow) {
                                if (position != ChatUsersActivity.this.removedUsersRow) {
                                    if (position != ChatUsersActivity.this.changeInfoRow && position != ChatUsersActivity.this.addUsersRow && position != ChatUsersActivity.this.pinMessagesRow && position != ChatUsersActivity.this.sendMessagesRow && position != ChatUsersActivity.this.sendMediaRow && position != ChatUsersActivity.this.sendStickersRow && position != ChatUsersActivity.this.embedLinksRow && position != ChatUsersActivity.this.sendPollsRow) {
                                        if (position == ChatUsersActivity.this.membersHeaderRow || position == ChatUsersActivity.this.contactsHeaderRow || position == ChatUsersActivity.this.botHeaderRow) {
                                            return 8;
                                        }
                                        return position == ChatUsersActivity.this.slowmodeSelectRow ? 9 : 0;
                                    }
                                    return 7;
                                }
                                return 6;
                            }
                            return 4;
                        }
                        return 1;
                    }
                    return 5;
                }
                return 3;
            }
            return 2;
        }

        public TLObject getItem(int position) {
            if (position < ChatUsersActivity.this.participantsStartRow || position >= ChatUsersActivity.this.participantsEndRow) {
                if (position < ChatUsersActivity.this.contactsStartRow || position >= ChatUsersActivity.this.contactsEndRow) {
                    if (position >= ChatUsersActivity.this.botStartRow && position < ChatUsersActivity.this.botEndRow) {
                        return (TLObject) ChatUsersActivity.this.bots.get(position - ChatUsersActivity.this.botStartRow);
                    }
                    return null;
                }
                return (TLObject) ChatUsersActivity.this.contacts.get(position - ChatUsersActivity.this.contactsStartRow);
            }
            return (TLObject) ChatUsersActivity.this.participants.get(position - ChatUsersActivity.this.participantsStartRow);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatUsersActivity$Aq8zujZjwSmfInpdvYDWONXE7fA
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$19$ChatUsersActivity();
            }
        };
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{HeaderCell.class, ManageChatUserCell.class, ManageChatTextCell.class, TextCheckCell2.class, TextSettingsCell.class, ChooseView.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader), new ThemeDescription(this.listView, 0, new Class[]{GraySectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_graySectionText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{GraySectionCell.class}, null, null, null, Theme.key_graySection), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell2.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell2.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell2.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switch2Track), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell2.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switch2TrackChecked), new ThemeDescription(this.listView, 0, new Class[]{ManageChatUserCell.class}, new String[]{"nameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{ManageChatUserCell.class}, new String[]{"statusColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteGrayText), new ThemeDescription(this.listView, 0, new Class[]{ManageChatUserCell.class}, new String[]{"statusOnlineColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteBlueText), new ThemeDescription(this.listView, 0, new Class[]{ManageChatUserCell.class}, null, new Drawable[]{Theme.avatar_savedDrawable}, null, Theme.key_avatar_text), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundRed), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundOrange), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundViolet), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundGreen), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundCyan), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundBlue), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundPink), new ThemeDescription(this.undoView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_undo_background), new ThemeDescription(this.undoView, 0, new Class[]{UndoView.class}, new String[]{"undoImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_cancelColor), new ThemeDescription(this.undoView, 0, new Class[]{UndoView.class}, new String[]{"undoTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_cancelColor), new ThemeDescription(this.undoView, 0, new Class[]{UndoView.class}, new String[]{"infoTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_infoColor), new ThemeDescription(this.undoView, 0, new Class[]{UndoView.class}, new String[]{"textPaint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_infoColor), new ThemeDescription(this.undoView, 0, new Class[]{UndoView.class}, new String[]{"progressPaint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_infoColor), new ThemeDescription(this.undoView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{UndoView.class}, new String[]{"leftImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_infoColor), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{ManageChatTextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{ManageChatTextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayIcon), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{ManageChatTextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueButton), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{ManageChatTextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueIcon)};
    }

    public /* synthetic */ void lambda$getThemeDescriptions$19$ChatUsersActivity() {
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            int count = recyclerListView.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = this.listView.getChildAt(a);
                if (child instanceof ManageChatUserCell) {
                    ((ManageChatUserCell) child).update(0);
                }
            }
        }
    }
}
