package im.uwrkaxlmjj.ui;

import android.app.DatePickerDialog;
import android.app.TimePickerDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.view.ViewGroup;
import android.widget.DatePicker;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.TimePicker;
import androidx.recyclerview.widget.DefaultItemAnimator;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.TwoStepVerificationActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.SimpleTextView;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.DialogRadioCell;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.PollEditTextCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextCheckCell2;
import im.uwrkaxlmjj.ui.cells.TextDetailCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.cells.UserCell2;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity;
import java.util.Calendar;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChatRightsEditActivity extends BaseFragment {
    private static final int MAX_RANK_LENGTH = 16;
    public static final int TYPE_ADMIN = 0;
    public static final int TYPE_BANNED = 1;
    private static final int done_button = 1;
    private int addAdminsRow;
    private int addUsersRow;
    private TLRPC.TL_chatAdminRights adminRights;
    private int banUsersRow;
    private TLRPC.TL_chatBannedRights bannedRights;
    private boolean canEdit;
    private int cantEditInfoRow;
    private int changeInfoRow;
    private int chatId;
    private String currentBannedRights;
    private TLRPC.Chat currentChat;
    private String currentRank;
    private int currentType;
    private TLRPC.User currentUser;
    private TLRPC.TL_chatBannedRights defaultBannedRights;
    private ChatRightsEditActivityDelegate delegate;
    private int deleteMessagesRow;
    private int editMesagesRow;
    private int embedLinksRow;
    private boolean initialIsSet;
    private String initialRank;
    private boolean isAddingNew;
    private boolean isChannel;
    private RecyclerListView listView;
    private ListAdapter listViewAdapter;
    private TLRPC.TL_chatAdminRights myAdminRights;
    private int pinMessagesRow;
    private int postMessagesRow;
    private int rankHeaderRow;
    private int rankInfoRow;
    private int rankRow;
    private int removeAdminRow;
    private int removeAdminShadowRow;
    private int rightsShadowRow;
    private int rowCount;
    private int sendMediaRow;
    private int sendMessagesRow;
    private int sendPollsRow;
    private int sendStickersRow;
    private int transferOwnerRow;
    private int transferOwnerShadowRow;
    private int untilDateRow;
    private int untilSectionRow;

    public interface ChatRightsEditActivityDelegate {
        void didChangeOwner(TLRPC.User user);

        void didSetRights(int i, TLRPC.TL_chatAdminRights tL_chatAdminRights, TLRPC.TL_chatBannedRights tL_chatBannedRights, String str);
    }

    public ChatRightsEditActivity(int userId, int channelId, TLRPC.TL_chatAdminRights rightsAdmin, TLRPC.TL_chatBannedRights rightsBannedDefault, TLRPC.TL_chatBannedRights rightsBanned, String rank, int type, boolean edit, boolean addingNew) {
        this.currentBannedRights = "";
        this.isAddingNew = addingNew;
        this.chatId = channelId;
        this.currentUser = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(userId));
        this.currentType = type;
        this.canEdit = edit;
        this.currentChat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.chatId));
        rank = rank == null ? "" : rank;
        this.currentRank = rank;
        this.initialRank = rank;
        TLRPC.Chat chat = this.currentChat;
        boolean z = true;
        if (chat != null) {
            this.isChannel = ChatObject.isChannel(chat) && !this.currentChat.megagroup;
            this.myAdminRights = this.currentChat.admin_rights;
        }
        if (this.myAdminRights == null) {
            TLRPC.TL_chatAdminRights tL_chatAdminRights = new TLRPC.TL_chatAdminRights();
            this.myAdminRights = tL_chatAdminRights;
            tL_chatAdminRights.add_admins = true;
            tL_chatAdminRights.pin_messages = true;
            tL_chatAdminRights.invite_users = true;
            tL_chatAdminRights.ban_users = true;
            tL_chatAdminRights.delete_messages = true;
            tL_chatAdminRights.edit_messages = true;
            tL_chatAdminRights.post_messages = true;
            tL_chatAdminRights.change_info = true;
        }
        if (type == 0) {
            TLRPC.TL_chatAdminRights tL_chatAdminRights2 = new TLRPC.TL_chatAdminRights();
            this.adminRights = tL_chatAdminRights2;
            if (rightsAdmin == null) {
                tL_chatAdminRights2.change_info = this.myAdminRights.change_info;
                this.adminRights.post_messages = this.myAdminRights.post_messages;
                this.adminRights.edit_messages = this.myAdminRights.edit_messages;
                this.adminRights.delete_messages = this.myAdminRights.delete_messages;
                this.adminRights.ban_users = this.myAdminRights.ban_users;
                this.adminRights.invite_users = this.myAdminRights.invite_users;
                this.adminRights.pin_messages = this.myAdminRights.pin_messages;
                this.initialIsSet = false;
            } else {
                tL_chatAdminRights2.change_info = rightsAdmin.change_info;
                this.adminRights.post_messages = rightsAdmin.post_messages;
                this.adminRights.edit_messages = rightsAdmin.edit_messages;
                this.adminRights.delete_messages = rightsAdmin.delete_messages;
                this.adminRights.ban_users = rightsAdmin.ban_users;
                this.adminRights.invite_users = rightsAdmin.invite_users;
                this.adminRights.pin_messages = rightsAdmin.pin_messages;
                this.adminRights.add_admins = rightsAdmin.add_admins;
                if (!this.adminRights.change_info && !this.adminRights.post_messages && !this.adminRights.edit_messages && !this.adminRights.delete_messages && !this.adminRights.ban_users && !this.adminRights.invite_users && !this.adminRights.pin_messages && !this.adminRights.add_admins) {
                    z = false;
                }
                this.initialIsSet = z;
            }
        } else {
            this.defaultBannedRights = rightsBannedDefault;
            if (rightsBannedDefault == null) {
                TLRPC.TL_chatBannedRights tL_chatBannedRights = new TLRPC.TL_chatBannedRights();
                this.defaultBannedRights = tL_chatBannedRights;
                tL_chatBannedRights.pin_messages = false;
                tL_chatBannedRights.change_info = false;
                tL_chatBannedRights.invite_users = false;
                tL_chatBannedRights.send_polls = false;
                tL_chatBannedRights.send_inline = false;
                tL_chatBannedRights.send_games = false;
                tL_chatBannedRights.send_gifs = false;
                tL_chatBannedRights.send_stickers = false;
                tL_chatBannedRights.embed_links = false;
                tL_chatBannedRights.send_messages = false;
                tL_chatBannedRights.send_media = false;
                tL_chatBannedRights.view_messages = false;
            }
            TLRPC.TL_chatBannedRights tL_chatBannedRights2 = new TLRPC.TL_chatBannedRights();
            this.bannedRights = tL_chatBannedRights2;
            if (rightsBanned == null) {
                tL_chatBannedRights2.pin_messages = false;
                tL_chatBannedRights2.change_info = false;
                tL_chatBannedRights2.invite_users = false;
                tL_chatBannedRights2.send_polls = false;
                tL_chatBannedRights2.send_inline = false;
                tL_chatBannedRights2.send_games = false;
                tL_chatBannedRights2.send_gifs = false;
                tL_chatBannedRights2.send_stickers = false;
                tL_chatBannedRights2.embed_links = false;
                tL_chatBannedRights2.send_messages = false;
                tL_chatBannedRights2.send_media = false;
                tL_chatBannedRights2.view_messages = false;
            } else {
                tL_chatBannedRights2.view_messages = rightsBanned.view_messages;
                this.bannedRights.send_messages = rightsBanned.send_messages;
                this.bannedRights.send_media = rightsBanned.send_media;
                this.bannedRights.send_stickers = rightsBanned.send_stickers;
                this.bannedRights.send_gifs = rightsBanned.send_gifs;
                this.bannedRights.send_games = rightsBanned.send_games;
                this.bannedRights.send_inline = rightsBanned.send_inline;
                this.bannedRights.embed_links = rightsBanned.embed_links;
                this.bannedRights.send_polls = rightsBanned.send_polls;
                this.bannedRights.invite_users = rightsBanned.invite_users;
                this.bannedRights.change_info = rightsBanned.change_info;
                this.bannedRights.pin_messages = rightsBanned.pin_messages;
                this.bannedRights.until_date = rightsBanned.until_date;
            }
            if (this.defaultBannedRights.view_messages) {
                this.bannedRights.view_messages = true;
            }
            if (this.defaultBannedRights.send_messages) {
                this.bannedRights.send_messages = true;
            }
            if (this.defaultBannedRights.send_media) {
                this.bannedRights.send_media = true;
            }
            if (this.defaultBannedRights.send_stickers) {
                this.bannedRights.send_stickers = true;
            }
            if (this.defaultBannedRights.send_gifs) {
                this.bannedRights.send_gifs = true;
            }
            if (this.defaultBannedRights.send_games) {
                this.bannedRights.send_games = true;
            }
            if (this.defaultBannedRights.send_inline) {
                this.bannedRights.send_inline = true;
            }
            if (this.defaultBannedRights.embed_links) {
                this.bannedRights.embed_links = true;
            }
            if (this.defaultBannedRights.send_polls) {
                this.bannedRights.send_polls = true;
            }
            if (this.defaultBannedRights.invite_users) {
                this.bannedRights.invite_users = true;
            }
            if (this.defaultBannedRights.change_info) {
                this.bannedRights.change_info = true;
            }
            if (this.defaultBannedRights.pin_messages) {
                this.bannedRights.pin_messages = true;
            }
            this.currentBannedRights = ChatObject.getBannedRightsString(this.bannedRights);
            if (rightsBanned != null && rightsBanned.view_messages) {
                z = false;
            }
            this.initialIsSet = z;
        }
        updateRows(false);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(final Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        if (this.currentType == 0) {
            this.actionBar.setTitle(LocaleController.getString("EditAdmin", R.string.EditAdmin));
        } else {
            this.actionBar.setTitle(LocaleController.getString("UserRestrictions", R.string.UserRestrictions));
        }
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.ChatRightsEditActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    if (ChatRightsEditActivity.this.checkDiscard()) {
                        ChatRightsEditActivity.this.finishFragment();
                    }
                } else if (id == 1) {
                    ChatRightsEditActivity.this.onDonePressed();
                }
            }
        });
        if (this.canEdit || (!this.isChannel && this.currentChat.creator && UserObject.isUserSelf(this.currentUser))) {
            ActionBarMenu menu = this.actionBar.createMenu();
            menu.addItemWithWidth(1, R.drawable.ic_done, AndroidUtilities.dp(56.0f), LocaleController.getString("Done", R.string.Done));
        }
        this.fragmentView = new FrameLayout(context);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        this.fragmentView.setFocusableInTouchMode(true);
        this.listView = new RecyclerListView(context);
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false);
        ((DefaultItemAnimator) this.listView.getItemAnimator()).setDelayAnimations(false);
        this.listView.setLayoutManager(linearLayoutManager);
        RecyclerListView recyclerListView = this.listView;
        ListAdapter listAdapter = new ListAdapter(context);
        this.listViewAdapter = listAdapter;
        recyclerListView.setAdapter(listAdapter);
        this.listView.setVerticalScrollbarPosition(LocaleController.isRTL ? 1 : 2);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1.0f));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$_gAcWvd-NOHd63mBe0Mp6S3GIwg
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$createView$7$ChatRightsEditActivity(context, view, i);
            }
        });
        return this.fragmentView;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r11v0 */
    /* JADX WARN: Type inference failed for: r11v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r11v4 */
    public /* synthetic */ void lambda$createView$7$ChatRightsEditActivity(Context context, View view, int i) {
        String string;
        TLRPC.Chat chat;
        if (!this.canEdit) {
            return;
        }
        int i2 = 2;
        ?? r11 = 0;
        z = false;
        boolean z = false;
        if (i != 0) {
            if (i == this.removeAdminRow) {
                int i3 = this.currentType;
                if (i3 == 0) {
                    MessagesController.getInstance(this.currentAccount).setUserAdminRole(this.chatId, this.currentUser, new TLRPC.TL_chatAdminRights(), this.currentRank, this.isChannel, getFragmentForAlert(0), this.isAddingNew);
                } else if (i3 == 1) {
                    TLRPC.TL_chatBannedRights tL_chatBannedRights = new TLRPC.TL_chatBannedRights();
                    this.bannedRights = tL_chatBannedRights;
                    tL_chatBannedRights.view_messages = true;
                    this.bannedRights.send_media = true;
                    this.bannedRights.send_messages = true;
                    this.bannedRights.send_stickers = true;
                    this.bannedRights.send_gifs = true;
                    this.bannedRights.send_games = true;
                    this.bannedRights.send_inline = true;
                    this.bannedRights.embed_links = true;
                    this.bannedRights.pin_messages = true;
                    this.bannedRights.send_polls = true;
                    this.bannedRights.invite_users = true;
                    this.bannedRights.change_info = true;
                    this.bannedRights.until_date = 0;
                    MessagesController.getInstance(this.currentAccount).setUserBannedRole(this.chatId, this.currentUser, this.bannedRights, this.isChannel, getFragmentForAlert(0));
                }
                ChatRightsEditActivityDelegate chatRightsEditActivityDelegate = this.delegate;
                if (chatRightsEditActivityDelegate != null) {
                    chatRightsEditActivityDelegate.didSetRights(0, this.adminRights, this.bannedRights, this.currentRank);
                }
                finishFragment();
                return;
            }
            if (i != this.transferOwnerRow) {
                if (i == this.untilDateRow) {
                    if (getParentActivity() == null) {
                        return;
                    }
                    final BottomSheet.Builder builder = new BottomSheet.Builder(context);
                    builder.setApplyTopPadding(false);
                    LinearLayout linearLayout = new LinearLayout(context);
                    linearLayout.setOrientation(1);
                    HeaderCell headerCell = new HeaderCell(context, true, 23, 15, false);
                    headerCell.setHeight(47);
                    headerCell.setText(LocaleController.getString("UserRestrictionsDuration", R.string.UserRestrictionsDuration));
                    linearLayout.addView(headerCell);
                    LinearLayout linearLayout2 = new LinearLayout(context);
                    linearLayout2.setOrientation(1);
                    linearLayout.addView(linearLayout2, LayoutHelper.createLinear(-1, -2));
                    BottomSheet.BottomSheetCell[] bottomSheetCellArr = new BottomSheet.BottomSheetCell[5];
                    int i4 = 0;
                    while (i4 < bottomSheetCellArr.length) {
                        bottomSheetCellArr[i4] = new BottomSheet.BottomSheetCell(context, r11);
                        bottomSheetCellArr[i4].setPadding(AndroidUtilities.dp(7.0f), r11, AndroidUtilities.dp(7.0f), r11);
                        bottomSheetCellArr[i4].setTag(Integer.valueOf(i4));
                        bottomSheetCellArr[i4].setBackgroundDrawable(Theme.getSelectorDrawable(r11));
                        if (i4 == 0) {
                            string = LocaleController.getString("UserRestrictionsUntilForever", R.string.UserRestrictionsUntilForever);
                        } else if (i4 == 1) {
                            string = LocaleController.formatPluralString("Days", 1);
                        } else if (i4 == i2) {
                            string = LocaleController.formatPluralString("Weeks", 1);
                        } else if (i4 == 3) {
                            string = LocaleController.formatPluralString("Months", 1);
                        } else {
                            string = LocaleController.getString("UserRestrictionsCustom", R.string.UserRestrictionsCustom);
                        }
                        bottomSheetCellArr[i4].setTextAndIcon(string, r11);
                        linearLayout2.addView(bottomSheetCellArr[i4], LayoutHelper.createLinear(-1, -2));
                        bottomSheetCellArr[i4].setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$em_YZBi8Tz9pFC26x21no7SYoxY
                            @Override // android.view.View.OnClickListener
                            public final void onClick(View view2) {
                                this.f$0.lambda$null$6$ChatRightsEditActivity(builder, view2);
                            }
                        });
                        i4++;
                        i2 = 2;
                        r11 = 0;
                    }
                    builder.setCustomView(linearLayout);
                    showDialog(builder.create());
                    return;
                }
                if (view instanceof TextCheckCell2) {
                    TextCheckCell2 textCheckCell2 = (TextCheckCell2) view;
                    if (textCheckCell2.hasIcon()) {
                        ToastUtils.show(R.string.UserRestrictionsDisabled);
                        return;
                    }
                    if (!textCheckCell2.isEnabled()) {
                        return;
                    }
                    textCheckCell2.setChecked(!textCheckCell2.isChecked());
                    if (i == this.changeInfoRow) {
                        if (this.currentType == 0) {
                            this.adminRights.change_info = !r2.change_info;
                        } else {
                            this.bannedRights.change_info = !r2.change_info;
                        }
                    } else if (i == this.postMessagesRow) {
                        this.adminRights.post_messages = !r2.post_messages;
                    } else if (i == this.editMesagesRow) {
                        this.adminRights.edit_messages = !r2.edit_messages;
                    } else if (i == this.deleteMessagesRow) {
                        this.adminRights.delete_messages = !r2.delete_messages;
                    } else if (i == this.addAdminsRow) {
                        this.adminRights.add_admins = !r2.add_admins;
                    } else if (i == this.banUsersRow) {
                        this.adminRights.ban_users = !r2.ban_users;
                    } else if (i == this.addUsersRow) {
                        if (this.currentType == 0) {
                            this.adminRights.invite_users = !r2.invite_users;
                        } else {
                            this.bannedRights.invite_users = !r2.invite_users;
                        }
                    } else if (i == this.pinMessagesRow) {
                        if (this.currentType == 0) {
                            this.adminRights.pin_messages = !r2.pin_messages;
                        } else {
                            this.bannedRights.pin_messages = !r2.pin_messages;
                        }
                    } else if (this.bannedRights != null) {
                        boolean z2 = !textCheckCell2.isChecked();
                        if (i == this.sendMessagesRow) {
                            this.bannedRights.send_messages = !r3.send_messages;
                        } else if (i == this.sendMediaRow) {
                            this.bannedRights.send_media = !r3.send_media;
                        } else if (i == this.sendStickersRow) {
                            TLRPC.TL_chatBannedRights tL_chatBannedRights2 = this.bannedRights;
                            boolean z3 = !tL_chatBannedRights2.send_stickers;
                            tL_chatBannedRights2.send_inline = z3;
                            tL_chatBannedRights2.send_gifs = z3;
                            tL_chatBannedRights2.send_games = z3;
                            tL_chatBannedRights2.send_stickers = z3;
                        } else if (i == this.embedLinksRow) {
                            this.bannedRights.embed_links = !r3.embed_links;
                        } else if (i == this.sendPollsRow) {
                            this.bannedRights.send_polls = !r3.send_polls;
                        }
                        if (z2) {
                            if (this.bannedRights.view_messages && !this.bannedRights.send_messages) {
                                this.bannedRights.send_messages = true;
                                RecyclerView.ViewHolder viewHolderFindViewHolderForAdapterPosition = this.listView.findViewHolderForAdapterPosition(this.sendMessagesRow);
                                if (viewHolderFindViewHolderForAdapterPosition != null) {
                                    ((TextCheckCell2) viewHolderFindViewHolderForAdapterPosition.itemView).setChecked(false);
                                }
                            }
                            if ((this.bannedRights.view_messages || this.bannedRights.send_messages) && !this.bannedRights.send_media) {
                                this.bannedRights.send_media = true;
                                RecyclerView.ViewHolder viewHolderFindViewHolderForAdapterPosition2 = this.listView.findViewHolderForAdapterPosition(this.sendMediaRow);
                                if (viewHolderFindViewHolderForAdapterPosition2 != null) {
                                    ((TextCheckCell2) viewHolderFindViewHolderForAdapterPosition2.itemView).setChecked(false);
                                }
                            }
                            if ((this.bannedRights.view_messages || this.bannedRights.send_messages) && !this.bannedRights.send_polls) {
                                this.bannedRights.send_polls = true;
                                RecyclerView.ViewHolder viewHolderFindViewHolderForAdapterPosition3 = this.listView.findViewHolderForAdapterPosition(this.sendPollsRow);
                                if (viewHolderFindViewHolderForAdapterPosition3 != null) {
                                    ((TextCheckCell2) viewHolderFindViewHolderForAdapterPosition3.itemView).setChecked(false);
                                }
                            }
                            if ((this.bannedRights.view_messages || this.bannedRights.send_messages) && !this.bannedRights.send_stickers) {
                                TLRPC.TL_chatBannedRights tL_chatBannedRights3 = this.bannedRights;
                                tL_chatBannedRights3.send_inline = true;
                                tL_chatBannedRights3.send_gifs = true;
                                tL_chatBannedRights3.send_games = true;
                                tL_chatBannedRights3.send_stickers = true;
                                RecyclerView.ViewHolder viewHolderFindViewHolderForAdapterPosition4 = this.listView.findViewHolderForAdapterPosition(this.sendStickersRow);
                                if (viewHolderFindViewHolderForAdapterPosition4 != null) {
                                    ((TextCheckCell2) viewHolderFindViewHolderForAdapterPosition4.itemView).setChecked(false);
                                }
                            }
                            if ((this.bannedRights.view_messages || this.bannedRights.send_messages) && !this.bannedRights.embed_links) {
                                this.bannedRights.embed_links = true;
                                RecyclerView.ViewHolder viewHolderFindViewHolderForAdapterPosition5 = this.listView.findViewHolderForAdapterPosition(this.embedLinksRow);
                                if (viewHolderFindViewHolderForAdapterPosition5 != null) {
                                    ((TextCheckCell2) viewHolderFindViewHolderForAdapterPosition5.itemView).setChecked(false);
                                }
                            }
                        } else {
                            if ((!this.bannedRights.send_messages || !this.bannedRights.embed_links || !this.bannedRights.send_inline || !this.bannedRights.send_media || !this.bannedRights.send_polls) && this.bannedRights.view_messages) {
                                this.bannedRights.view_messages = false;
                            }
                            if ((!this.bannedRights.embed_links || !this.bannedRights.send_inline || !this.bannedRights.send_media || !this.bannedRights.send_polls) && this.bannedRights.send_messages) {
                                this.bannedRights.send_messages = false;
                                RecyclerView.ViewHolder viewHolderFindViewHolderForAdapterPosition6 = this.listView.findViewHolderForAdapterPosition(this.sendMessagesRow);
                                if (viewHolderFindViewHolderForAdapterPosition6 != null) {
                                    ((TextCheckCell2) viewHolderFindViewHolderForAdapterPosition6.itemView).setChecked(true);
                                }
                            }
                        }
                    }
                    updateRows(true);
                    return;
                }
                return;
            }
            AlertDialog.Builder builder2 = new AlertDialog.Builder(getParentActivity());
            if (this.isChannel) {
                builder2.setTitle(LocaleController.getString("EditAdminChannelTransfer", R.string.EditAdminChannelTransfer));
            } else {
                builder2.setTitle(LocaleController.getString("EditAdminGroupTransfer", R.string.EditAdminGroupTransfer));
            }
            builder2.setMessage(AndroidUtilities.replaceTags(LocaleController.formatString("EditAdminTransferReadyAlertText", R.string.EditAdminTransferReadyAlertText, this.currentChat.title, UserObject.getFirstName(this.currentUser))));
            builder2.setPositiveButton(LocaleController.getString("EditAdminTransferChangeOwner", R.string.EditAdminTransferChangeOwner), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$Q8WoeJFr3H1z69CkkpN4NWtWEcE
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i5) {
                    this.f$0.lambda$null$0$ChatRightsEditActivity(dialogInterface, i5);
                }
            });
            builder2.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder2.create());
            return;
        }
        if (!this.currentUser.self && (chat = this.currentChat) != null && chat.megagroup && (this.currentChat.flags & ConnectionsManager.FileTypeVideo) != 0 && !this.currentUser.mutual_contact && !ChatObject.hasAdminRights(this.currentChat)) {
            ToastUtils.show(R.string.ForbidViewUserInfoTips);
            return;
        }
        Bundle bundle = new Bundle();
        bundle.putInt("user_id", this.currentUser.id);
        if (this.currentChat.megagroup && (33554432 & this.currentChat.flags) != 0) {
            z = true;
        }
        bundle.putBoolean("forbid_add_contact", z);
        bundle.putBoolean("has_admin_right", ChatObject.hasAdminRights(this.currentChat));
        bundle.putInt("from_type", 2);
        presentFragment(new NewProfileActivity(bundle));
    }

    public /* synthetic */ void lambda$null$0$ChatRightsEditActivity(DialogInterface dialogInterface, int i) {
        lambda$null$9$ChatRightsEditActivity(null, null);
    }

    public /* synthetic */ void lambda$null$6$ChatRightsEditActivity(BottomSheet.Builder builder, View v2) {
        Integer tag = (Integer) v2.getTag();
        int iIntValue = tag.intValue();
        if (iIntValue == 0) {
            this.bannedRights.until_date = 0;
            this.listViewAdapter.notifyItemChanged(this.untilDateRow);
        } else if (iIntValue == 1) {
            this.bannedRights.until_date = ConnectionsManager.getInstance(this.currentAccount).getCurrentTime() + 86400;
            this.listViewAdapter.notifyItemChanged(this.untilDateRow);
        } else if (iIntValue == 2) {
            this.bannedRights.until_date = ConnectionsManager.getInstance(this.currentAccount).getCurrentTime() + 604800;
            this.listViewAdapter.notifyItemChanged(this.untilDateRow);
        } else if (iIntValue == 3) {
            this.bannedRights.until_date = ConnectionsManager.getInstance(this.currentAccount).getCurrentTime() + 2592000;
            this.listViewAdapter.notifyItemChanged(this.untilDateRow);
        } else if (iIntValue == 4) {
            Calendar calendar = Calendar.getInstance();
            int year = calendar.get(1);
            int monthOfYear = calendar.get(2);
            int dayOfMonth = calendar.get(5);
            try {
                DatePickerDialog datePickerDialog = new DatePickerDialog(getParentActivity(), new DatePickerDialog.OnDateSetListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$Pm_tSlStTO_fKX9Qob95H9Imp2I
                    @Override // android.app.DatePickerDialog.OnDateSetListener
                    public final void onDateSet(DatePicker datePicker, int i, int i2, int i3) {
                        this.f$0.lambda$null$3$ChatRightsEditActivity(datePicker, i, i2, i3);
                    }
                }, year, monthOfYear, dayOfMonth);
                final DatePicker datePicker = datePickerDialog.getDatePicker();
                Calendar date = Calendar.getInstance();
                date.setTimeInMillis(System.currentTimeMillis());
                date.set(11, date.getMinimum(11));
                date.set(12, date.getMinimum(12));
                date.set(13, date.getMinimum(13));
                date.set(14, date.getMinimum(14));
                datePicker.setMinDate(date.getTimeInMillis());
                date.setTimeInMillis(System.currentTimeMillis() + 31536000000L);
                date.set(11, date.getMaximum(11));
                date.set(12, date.getMaximum(12));
                date.set(13, date.getMaximum(13));
                date.set(14, date.getMaximum(14));
                datePicker.setMaxDate(date.getTimeInMillis());
                datePickerDialog.setButton(-1, LocaleController.getString("Set", R.string.Set), datePickerDialog);
                datePickerDialog.setButton(-2, LocaleController.getString("Cancel", R.string.Cancel), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$BaSeTD4BYFUDb6VMBkKE53bq93g
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        ChatRightsEditActivity.lambda$null$4(dialogInterface, i);
                    }
                });
                if (Build.VERSION.SDK_INT >= 21) {
                    datePickerDialog.setOnShowListener(new DialogInterface.OnShowListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$VUbWtoBlNMDPDRjsRMOAUJlzbrI
                        @Override // android.content.DialogInterface.OnShowListener
                        public final void onShow(DialogInterface dialogInterface) {
                            ChatRightsEditActivity.lambda$null$5(datePicker, dialogInterface);
                        }
                    });
                }
                showDialog(datePickerDialog);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        builder.getDismissRunnable().run();
    }

    public /* synthetic */ void lambda$null$3$ChatRightsEditActivity(DatePicker view1, int year1, int month, int dayOfMonth1) {
        Calendar calendar1 = Calendar.getInstance();
        calendar1.clear();
        calendar1.set(year1, month, dayOfMonth1);
        final int time = (int) (calendar1.getTime().getTime() / 1000);
        try {
            TimePickerDialog timePickerDialog = new TimePickerDialog(getParentActivity(), new TimePickerDialog.OnTimeSetListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$dFkiu6G90g6w8FL29fwOQ239eL8
                @Override // android.app.TimePickerDialog.OnTimeSetListener
                public final void onTimeSet(TimePicker timePicker, int i, int i2) {
                    this.f$0.lambda$null$1$ChatRightsEditActivity(time, timePicker, i, i2);
                }
            }, 0, 0, true);
            timePickerDialog.setButton(-1, LocaleController.getString("Set", R.string.Set), timePickerDialog);
            timePickerDialog.setButton(-2, LocaleController.getString("Cancel", R.string.Cancel), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$YGHi96KEKIFqITA_n5nkglcSMNQ
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    ChatRightsEditActivity.lambda$null$2(dialogInterface, i);
                }
            });
            showDialog(timePickerDialog);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$null$1$ChatRightsEditActivity(int time, TimePicker view11, int hourOfDay, int minute) {
        this.bannedRights.until_date = (hourOfDay * 3600) + time + (minute * 60);
        this.listViewAdapter.notifyItemChanged(this.untilDateRow);
    }

    static /* synthetic */ void lambda$null$2(DialogInterface dialog131, int which) {
    }

    static /* synthetic */ void lambda$null$4(DialogInterface dialog1, int which) {
    }

    static /* synthetic */ void lambda$null$5(DatePicker datePicker, DialogInterface dialog12) {
        int count = datePicker.getChildCount();
        for (int b = 0; b < count; b++) {
            View child = datePicker.getChildAt(b);
            ViewGroup.LayoutParams layoutParams = child.getLayoutParams();
            layoutParams.width = -1;
            child.setLayoutParams(layoutParams);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listViewAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
        AndroidUtilities.requestAdjustResize(getParentActivity(), this.classGuid);
    }

    private boolean isDefaultAdminRights() {
        return (this.adminRights.change_info && this.adminRights.delete_messages && this.adminRights.ban_users && this.adminRights.invite_users && this.adminRights.pin_messages && !this.adminRights.add_admins) || !(this.adminRights.change_info || this.adminRights.delete_messages || this.adminRights.ban_users || this.adminRights.invite_users || this.adminRights.pin_messages || this.adminRights.add_admins);
    }

    private boolean hasAllAdminRights() {
        return this.isChannel ? this.adminRights.change_info && this.adminRights.post_messages && this.adminRights.edit_messages && this.adminRights.delete_messages && this.adminRights.invite_users && this.adminRights.add_admins : this.adminRights.change_info && this.adminRights.delete_messages && this.adminRights.ban_users && this.adminRights.invite_users && this.adminRights.pin_messages && this.adminRights.add_admins;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: initTransfer, reason: merged with bridge method [inline-methods] */
    public void lambda$null$9$ChatRightsEditActivity(final TLRPC.InputCheckPasswordSRP srp, final TwoStepVerificationActivity passwordFragment) {
        if (getParentActivity() == null) {
            return;
        }
        if (srp != null && !ChatObject.isChannel(this.currentChat)) {
            MessagesController.getInstance(this.currentAccount).convertToMegaGroup(getParentActivity(), this.chatId, this, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$dG6-z1ivIVmVW0bxp6mAPMRX3M8
                @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
                public final void run(int i) {
                    this.f$0.lambda$initTransfer$8$ChatRightsEditActivity(srp, passwordFragment, i);
                }
            });
            return;
        }
        final TLRPC.TL_channels_editCreator req = new TLRPC.TL_channels_editCreator();
        if (ChatObject.isChannel(this.currentChat)) {
            req.channel = new TLRPC.TL_inputChannel();
            req.channel.channel_id = this.currentChat.id;
            req.channel.access_hash = this.currentChat.access_hash;
        } else {
            req.channel = new TLRPC.TL_inputChannelEmpty();
        }
        req.password = srp != null ? srp : new TLRPC.TL_inputCheckPasswordEmpty();
        req.user_id = getMessagesController().getInputUser(this.currentUser);
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$QRBMEzNXOfy_uVVu55PigmwpUDw
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$initTransfer$15$ChatRightsEditActivity(srp, passwordFragment, req, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$initTransfer$8$ChatRightsEditActivity(TLRPC.InputCheckPasswordSRP srp, TwoStepVerificationActivity passwordFragment, int param) {
        this.chatId = param;
        this.currentChat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(param));
        lambda$null$9$ChatRightsEditActivity(srp, passwordFragment);
    }

    public /* synthetic */ void lambda$initTransfer$15$ChatRightsEditActivity(final TLRPC.InputCheckPasswordSRP srp, final TwoStepVerificationActivity passwordFragment, final TLRPC.TL_channels_editCreator req, TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$uH7JRO5GNztSgnWYQFBKVBYIung
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$14$ChatRightsEditActivity(error, srp, passwordFragment, req);
            }
        });
    }

    public /* synthetic */ void lambda$null$14$ChatRightsEditActivity(TLRPC.TL_error error, TLRPC.InputCheckPasswordSRP srp, final TwoStepVerificationActivity passwordFragment, TLRPC.TL_channels_editCreator req) {
        if (error == null) {
            if (srp != null) {
                this.delegate.didChangeOwner(this.currentUser);
                removeSelfFromStack();
                passwordFragment.needHideProgress();
                passwordFragment.finishFragment();
                return;
            }
            this.delegate.didChangeOwner(this.currentUser);
            finishFragment();
            return;
        }
        if (getParentActivity() == null) {
            return;
        }
        if ("PASSWORD_HASH_INVALID".equals(error.text)) {
            if (srp == null) {
                AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                if (this.isChannel) {
                    builder.setTitle(LocaleController.getString("EditAdminChannelTransfer", R.string.EditAdminChannelTransfer));
                } else {
                    builder.setTitle(LocaleController.getString("EditAdminGroupTransfer", R.string.EditAdminGroupTransfer));
                }
                builder.setMessage(AndroidUtilities.replaceTags(LocaleController.formatString("EditAdminTransferReadyAlertText", R.string.EditAdminTransferReadyAlertText, this.currentChat.title, UserObject.getFirstName(this.currentUser))));
                builder.setPositiveButton(LocaleController.getString("EditAdminTransferChangeOwner", R.string.EditAdminTransferChangeOwner), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$j8_MIrLjgUMK5HV07nzSm5zWpdI
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$10$ChatRightsEditActivity(dialogInterface, i);
                    }
                });
                builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                showDialog(builder.create());
                return;
            }
            return;
        }
        if ("PASSWORD_MISSING".equals(error.text) || error.text.startsWith("PASSWORD_TOO_FRESH_") || error.text.startsWith("SESSION_TOO_FRESH_")) {
            if (passwordFragment != null) {
                passwordFragment.needHideProgress();
            }
            AlertDialog.Builder builder2 = new AlertDialog.Builder(getParentActivity());
            builder2.setTitle(LocaleController.getString("EditAdminTransferAlertTitle", R.string.EditAdminTransferAlertTitle));
            LinearLayout linearLayout = new LinearLayout(getParentActivity());
            linearLayout.setPadding(AndroidUtilities.dp(24.0f), AndroidUtilities.dp(2.0f), AndroidUtilities.dp(24.0f), 0);
            linearLayout.setOrientation(1);
            builder2.setView(linearLayout);
            TextView messageTextView = new TextView(getParentActivity());
            messageTextView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
            messageTextView.setTextSize(1, 16.0f);
            messageTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
            if (this.isChannel) {
                messageTextView.setText(AndroidUtilities.replaceTags(LocaleController.formatString("EditChannelAdminTransferAlertText", R.string.EditChannelAdminTransferAlertText, UserObject.getFirstName(this.currentUser))));
            } else {
                messageTextView.setText(AndroidUtilities.replaceTags(LocaleController.formatString("EditAdminTransferAlertText", R.string.EditAdminTransferAlertText, UserObject.getFirstName(this.currentUser))));
            }
            linearLayout.addView(messageTextView, LayoutHelper.createLinear(-1, -2));
            LinearLayout linearLayout2 = new LinearLayout(getParentActivity());
            linearLayout2.setOrientation(0);
            linearLayout.addView(linearLayout2, LayoutHelper.createLinear(-1, -2, 0.0f, 11.0f, 0.0f, 0.0f));
            ImageView dotImageView = new ImageView(getParentActivity());
            dotImageView.setImageResource(R.drawable.list_circle);
            dotImageView.setPadding(LocaleController.isRTL ? AndroidUtilities.dp(11.0f) : 0, AndroidUtilities.dp(9.0f), LocaleController.isRTL ? 0 : AndroidUtilities.dp(11.0f), 0);
            dotImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogTextBlack), PorterDuff.Mode.MULTIPLY));
            TextView messageTextView2 = new TextView(getParentActivity());
            messageTextView2.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
            messageTextView2.setTextSize(1, 16.0f);
            messageTextView2.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
            messageTextView2.setText(AndroidUtilities.replaceTags(LocaleController.getString("EditAdminTransferAlertText1", R.string.EditAdminTransferAlertText1)));
            if (LocaleController.isRTL) {
                linearLayout2.addView(messageTextView2, LayoutHelper.createLinear(-1, -2));
                linearLayout2.addView(dotImageView, LayoutHelper.createLinear(-2, -2, 5));
            } else {
                linearLayout2.addView(dotImageView, LayoutHelper.createLinear(-2, -2));
                linearLayout2.addView(messageTextView2, LayoutHelper.createLinear(-1, -2));
            }
            LinearLayout linearLayout22 = new LinearLayout(getParentActivity());
            linearLayout22.setOrientation(0);
            linearLayout.addView(linearLayout22, LayoutHelper.createLinear(-1, -2, 0.0f, 11.0f, 0.0f, 0.0f));
            ImageView dotImageView2 = new ImageView(getParentActivity());
            dotImageView2.setImageResource(R.drawable.list_circle);
            dotImageView2.setPadding(LocaleController.isRTL ? AndroidUtilities.dp(11.0f) : 0, AndroidUtilities.dp(9.0f), LocaleController.isRTL ? 0 : AndroidUtilities.dp(11.0f), 0);
            dotImageView2.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogTextBlack), PorterDuff.Mode.MULTIPLY));
            TextView messageTextView3 = new TextView(getParentActivity());
            messageTextView3.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
            messageTextView3.setTextSize(1, 16.0f);
            messageTextView3.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
            messageTextView3.setText(AndroidUtilities.replaceTags(LocaleController.getString("EditAdminTransferAlertText2", R.string.EditAdminTransferAlertText2)));
            if (LocaleController.isRTL) {
                linearLayout22.addView(messageTextView3, LayoutHelper.createLinear(-1, -2));
                linearLayout22.addView(dotImageView2, LayoutHelper.createLinear(-2, -2, 5));
            } else {
                linearLayout22.addView(dotImageView2, LayoutHelper.createLinear(-2, -2));
                linearLayout22.addView(messageTextView3, LayoutHelper.createLinear(-1, -2));
            }
            if ("PASSWORD_MISSING".equals(error.text)) {
                builder2.setPositiveButton(LocaleController.getString("EditAdminTransferSetPassword", R.string.EditAdminTransferSetPassword), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$3oN7uxvA-qDxHiuPUcuXrAvhRkQ
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$11$ChatRightsEditActivity(dialogInterface, i);
                    }
                });
                builder2.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            } else {
                TextView messageTextView4 = new TextView(getParentActivity());
                messageTextView4.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
                messageTextView4.setTextSize(1, 16.0f);
                messageTextView4.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
                messageTextView4.setText(LocaleController.getString("EditAdminTransferAlertText3", R.string.EditAdminTransferAlertText3));
                linearLayout.addView(messageTextView4, LayoutHelper.createLinear(-1, -2, 0.0f, 11.0f, 0.0f, 0.0f));
                builder2.setNegativeButton(LocaleController.getString("OK", R.string.OK), null);
            }
            showDialog(builder2.create());
            return;
        }
        if ("SRP_ID_INVALID".equals(error.text)) {
            TLRPC.TL_account_getPassword getPasswordReq = new TLRPC.TL_account_getPassword();
            ConnectionsManager.getInstance(this.currentAccount).sendRequest(getPasswordReq, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$wPuEL1lbGzpdLyKGn-IsTp2AUCo
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$13$ChatRightsEditActivity(passwordFragment, tLObject, tL_error);
                }
            }, 8);
        } else {
            if (passwordFragment != null) {
                passwordFragment.needHideProgress();
                passwordFragment.finishFragment();
            }
            AlertsCreator.showAddUserAlert(error.text, this, this.isChannel, req);
        }
    }

    public /* synthetic */ void lambda$null$10$ChatRightsEditActivity(DialogInterface dialogInterface, int i) {
        final TwoStepVerificationActivity fragment = new TwoStepVerificationActivity(0);
        fragment.setDelegate(new TwoStepVerificationActivity.TwoStepVerificationActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$WkvAkMkqWQeMCEtU2pqRHOObpRE
            @Override // im.uwrkaxlmjj.ui.TwoStepVerificationActivity.TwoStepVerificationActivityDelegate
            public final void didEnterPassword(TLRPC.InputCheckPasswordSRP inputCheckPasswordSRP) {
                this.f$0.lambda$null$9$ChatRightsEditActivity(fragment, inputCheckPasswordSRP);
            }
        });
        presentFragment(fragment);
    }

    public /* synthetic */ void lambda$null$11$ChatRightsEditActivity(DialogInterface dialogInterface, int i) {
        presentFragment(new TwoStepVerificationActivity(0));
    }

    public /* synthetic */ void lambda$null$13$ChatRightsEditActivity(final TwoStepVerificationActivity passwordFragment, final TLObject response2, final TLRPC.TL_error error2) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$ausX731cS2Q8vxWGzSxYmngPPls
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$12$ChatRightsEditActivity(error2, response2, passwordFragment);
            }
        });
    }

    public /* synthetic */ void lambda$null$12$ChatRightsEditActivity(TLRPC.TL_error error2, TLObject response2, TwoStepVerificationActivity passwordFragment) {
        if (error2 == null) {
            TLRPC.TL_account_password currentPassword = (TLRPC.TL_account_password) response2;
            passwordFragment.setCurrentPasswordInfo(null, currentPassword);
            TwoStepVerificationActivity.initPasswordNewAlgo(currentPassword);
            lambda$null$9$ChatRightsEditActivity(passwordFragment.getNewSrpPassword(), passwordFragment);
        }
    }

    private void updateRows(boolean update) {
        int i;
        int transferOwnerShadowRowPrev = Math.min(this.transferOwnerShadowRow, this.transferOwnerRow);
        this.changeInfoRow = -1;
        this.postMessagesRow = -1;
        this.editMesagesRow = -1;
        this.deleteMessagesRow = -1;
        this.addAdminsRow = -1;
        this.banUsersRow = -1;
        this.addUsersRow = -1;
        this.pinMessagesRow = -1;
        this.rightsShadowRow = -1;
        this.removeAdminRow = -1;
        this.removeAdminShadowRow = -1;
        this.cantEditInfoRow = -1;
        this.transferOwnerShadowRow = -1;
        this.transferOwnerRow = -1;
        this.rankHeaderRow = -1;
        this.rankRow = -1;
        this.rankInfoRow = -1;
        this.sendMessagesRow = -1;
        this.sendMediaRow = -1;
        this.sendStickersRow = -1;
        this.sendPollsRow = -1;
        this.embedLinksRow = -1;
        this.untilSectionRow = -1;
        this.untilDateRow = -1;
        this.rowCount = 3;
        int i2 = this.currentType;
        if (i2 == 0) {
            if (this.isChannel) {
                int i3 = 3 + 1;
                this.rowCount = i3;
                this.changeInfoRow = 3;
                int i4 = i3 + 1;
                this.rowCount = i4;
                this.postMessagesRow = i3;
                int i5 = i4 + 1;
                this.rowCount = i5;
                this.editMesagesRow = i4;
                int i6 = i5 + 1;
                this.rowCount = i6;
                this.deleteMessagesRow = i5;
                int i7 = i6 + 1;
                this.rowCount = i7;
                this.addUsersRow = i6;
                this.rowCount = i7 + 1;
                this.addAdminsRow = i7;
            } else {
                int i8 = 3 + 1;
                this.rowCount = i8;
                this.changeInfoRow = 3;
                int i9 = i8 + 1;
                this.rowCount = i9;
                this.deleteMessagesRow = i8;
                int i10 = i9 + 1;
                this.rowCount = i10;
                this.banUsersRow = i9;
                int i11 = i10 + 1;
                this.rowCount = i11;
                this.addUsersRow = i10;
                int i12 = i11 + 1;
                this.rowCount = i12;
                this.pinMessagesRow = i11;
                this.rowCount = i12 + 1;
                this.addAdminsRow = i12;
            }
        } else if (i2 == 1) {
            int i13 = 3 + 1;
            this.rowCount = i13;
            this.sendMessagesRow = 3;
            int i14 = i13 + 1;
            this.rowCount = i14;
            this.sendMediaRow = i13;
            int i15 = i14 + 1;
            this.rowCount = i15;
            this.sendStickersRow = i14;
            int i16 = i15 + 1;
            this.rowCount = i16;
            this.sendPollsRow = i15;
            int i17 = i16 + 1;
            this.rowCount = i17;
            this.embedLinksRow = i16;
            int i18 = i17 + 1;
            this.rowCount = i18;
            this.addUsersRow = i17;
            int i19 = i18 + 1;
            this.rowCount = i19;
            this.pinMessagesRow = i18;
            int i20 = i19 + 1;
            this.rowCount = i20;
            this.changeInfoRow = i19;
            int i21 = i20 + 1;
            this.rowCount = i21;
            this.untilSectionRow = i20;
            this.rowCount = i21 + 1;
            this.untilDateRow = i21;
        }
        boolean z = this.canEdit;
        if (z) {
            if (!this.isChannel && this.currentType == 0) {
                int i22 = this.rowCount;
                int i23 = i22 + 1;
                this.rowCount = i23;
                this.rightsShadowRow = i22;
                int i24 = i23 + 1;
                this.rowCount = i24;
                this.rankHeaderRow = i23;
                int i25 = i24 + 1;
                this.rowCount = i25;
                this.rankRow = i24;
                this.rowCount = i25 + 1;
                this.rankInfoRow = i25;
            }
            TLRPC.Chat chat = this.currentChat;
            if (chat != null && chat.creator && this.currentType == 0 && hasAllAdminRights() && !this.currentUser.bot) {
                int i26 = this.rowCount;
                int i27 = i26 + 1;
                this.rowCount = i27;
                this.transferOwnerRow = i26;
                this.rowCount = i27 + 1;
                this.transferOwnerShadowRow = i27;
            }
            if (this.initialIsSet) {
                int i28 = this.rowCount;
                int i29 = i28 + 1;
                this.rowCount = i29;
                this.rightsShadowRow = i28;
                int i30 = i29 + 1;
                this.rowCount = i30;
                this.removeAdminRow = i29;
                this.rowCount = i30 + 1;
                this.removeAdminShadowRow = i30;
                this.cantEditInfoRow = -1;
            }
        } else {
            this.removeAdminRow = -1;
            this.removeAdminShadowRow = -1;
            if (this.currentType == 0 && !z) {
                this.rightsShadowRow = -1;
                int i31 = this.rowCount;
                this.rowCount = i31 + 1;
                this.cantEditInfoRow = i31;
            } else {
                int i32 = this.rowCount;
                this.rowCount = i32 + 1;
                this.rightsShadowRow = i32;
            }
        }
        if (update) {
            if (transferOwnerShadowRowPrev == -1 && (i = this.transferOwnerShadowRow) != -1) {
                this.listViewAdapter.notifyItemRangeInserted(Math.min(i, this.transferOwnerRow), 2);
            } else if (transferOwnerShadowRowPrev != -1 && this.transferOwnerShadowRow == -1) {
                this.listViewAdapter.notifyItemRangeRemoved(transferOwnerShadowRowPrev, 2);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x0027, code lost:
    
        if (r0.codePointCount(0, r0.length()) > 16) goto L13;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onDonePressed() {
        /*
            Method dump skipped, instruction units count: 322
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatRightsEditActivity.onDonePressed():void");
    }

    public /* synthetic */ void lambda$onDonePressed$16$ChatRightsEditActivity(int param) {
        this.chatId = param;
        this.currentChat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(param));
        onDonePressed();
    }

    public void setDelegate(ChatRightsEditActivityDelegate channelRightsEditActivityDelegate) {
        this.delegate = channelRightsEditActivityDelegate;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean checkDiscard() {
        boolean changed;
        if (this.currentType == 1) {
            String newBannedRights = ChatObject.getBannedRightsString(this.bannedRights);
            changed = !this.currentBannedRights.equals(newBannedRights);
        } else {
            changed = !this.initialRank.equals(this.currentRank);
        }
        if (!changed) {
            return true;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("UserRestrictionsApplyChanges", R.string.UserRestrictionsApplyChanges));
        TLRPC.Chat chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.chatId));
        builder.setMessage(AndroidUtilities.replaceTags(LocaleController.formatString("UserRestrictionsApplyChangesText", R.string.UserRestrictionsApplyChangesText, chat.title)));
        builder.setPositiveButton(LocaleController.getString("ApplyTheme", R.string.ApplyTheme), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$JQci860ylfPgD_itQB97aUdqD0g
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$checkDiscard$17$ChatRightsEditActivity(dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("PassportDiscard", R.string.PassportDiscard), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$daJBe9NTtZRl19u0WedgfUo-l1E
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$checkDiscard$18$ChatRightsEditActivity(dialogInterface, i);
            }
        });
        showDialog(builder.create());
        return false;
    }

    public /* synthetic */ void lambda$checkDiscard$17$ChatRightsEditActivity(DialogInterface dialogInterface, int i) {
        onDonePressed();
    }

    public /* synthetic */ void lambda$checkDiscard$18$ChatRightsEditActivity(DialogInterface dialog, int which) {
        finishFragment();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setTextLeft(View cell) {
        if (cell instanceof HeaderCell) {
            HeaderCell headerCell = (HeaderCell) cell;
            String str = this.currentRank;
            int left = 16 - (str != null ? str.codePointCount(0, str.length()) : 0);
            if (left <= 4.8f) {
                headerCell.setText2(String.format("%d", Integer.valueOf(left)));
                SimpleTextView textView = headerCell.getTextView2();
                String key = left < 0 ? Theme.key_windowBackgroundWhiteRedText5 : Theme.key_windowBackgroundWhiteGrayText3;
                textView.setTextColor(Theme.getColor(key));
                textView.setTag(key);
                return;
            }
            headerCell.setText2("");
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        return checkDiscard();
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private boolean ignoreTextChange;
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            if (!ChatRightsEditActivity.this.canEdit) {
                return false;
            }
            int type = holder.getItemViewType();
            if (ChatRightsEditActivity.this.currentType == 0 && type == 4) {
                int position = holder.getAdapterPosition();
                if (position == ChatRightsEditActivity.this.changeInfoRow) {
                    return ChatRightsEditActivity.this.myAdminRights.change_info;
                }
                if (position == ChatRightsEditActivity.this.postMessagesRow) {
                    return ChatRightsEditActivity.this.myAdminRights.post_messages;
                }
                if (position == ChatRightsEditActivity.this.editMesagesRow) {
                    return ChatRightsEditActivity.this.myAdminRights.edit_messages;
                }
                if (position == ChatRightsEditActivity.this.deleteMessagesRow) {
                    return ChatRightsEditActivity.this.myAdminRights.delete_messages;
                }
                if (position == ChatRightsEditActivity.this.addAdminsRow) {
                    return ChatRightsEditActivity.this.myAdminRights.add_admins;
                }
                if (position == ChatRightsEditActivity.this.banUsersRow) {
                    return ChatRightsEditActivity.this.myAdminRights.ban_users;
                }
                if (position == ChatRightsEditActivity.this.addUsersRow) {
                    return ChatRightsEditActivity.this.myAdminRights.invite_users;
                }
                if (position == ChatRightsEditActivity.this.pinMessagesRow) {
                    return ChatRightsEditActivity.this.myAdminRights.pin_messages;
                }
            }
            return ((ChatRightsEditActivity.this.currentType == 1 && type == 0) || type == 3 || type == 1 || type == 5) ? false : true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return ChatRightsEditActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int i) {
            View shadowSectionCell;
            switch (i) {
                case 0:
                    UserCell2 userCell2 = new UserCell2(this.mContext, 4, 0);
                    userCell2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    shadowSectionCell = userCell2;
                    break;
                case 1:
                    TextInfoPrivacyCell textInfoPrivacyCell = new TextInfoPrivacyCell(this.mContext);
                    textInfoPrivacyCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                    shadowSectionCell = textInfoPrivacyCell;
                    break;
                case 2:
                    TextSettingsCell textSettingsCell = new TextSettingsCell(this.mContext);
                    textSettingsCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    shadowSectionCell = textSettingsCell;
                    break;
                case 3:
                    HeaderCell headerCell = new HeaderCell(this.mContext, false, 21, 15, true);
                    headerCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    shadowSectionCell = headerCell;
                    break;
                case 4:
                    TextCheckCell2 textCheckCell2 = new TextCheckCell2(this.mContext);
                    textCheckCell2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    shadowSectionCell = textCheckCell2;
                    break;
                case 5:
                    shadowSectionCell = new ShadowSectionCell(this.mContext);
                    break;
                case 6:
                    TextDetailCell textDetailCell = new TextDetailCell(this.mContext);
                    textDetailCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    shadowSectionCell = textDetailCell;
                    break;
                default:
                    PollEditTextCell pollEditTextCell = new PollEditTextCell(this.mContext, null);
                    pollEditTextCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    pollEditTextCell.addTextWatcher(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.ChatRightsEditActivity.ListAdapter.1
                        @Override // android.text.TextWatcher
                        public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                        }

                        @Override // android.text.TextWatcher
                        public void onTextChanged(CharSequence s, int start, int before, int count) {
                        }

                        @Override // android.text.TextWatcher
                        public void afterTextChanged(Editable s) {
                            if (ListAdapter.this.ignoreTextChange) {
                                return;
                            }
                            ChatRightsEditActivity.this.currentRank = s.toString();
                            RecyclerView.ViewHolder holder = ChatRightsEditActivity.this.listView.findViewHolderForAdapterPosition(ChatRightsEditActivity.this.rankHeaderRow);
                            if (holder != null) {
                                ChatRightsEditActivity.this.setTextLeft(holder.itemView);
                            }
                        }
                    });
                    shadowSectionCell = pollEditTextCell;
                    break;
            }
            return new RecyclerListView.Holder(shadowSectionCell);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String hint;
            String value;
            String hint2;
            boolean z = false;
            switch (holder.getItemViewType()) {
                case 0:
                    UserCell2 userCell2 = (UserCell2) holder.itemView;
                    userCell2.setData(ChatRightsEditActivity.this.currentUser, null, null, 0);
                    break;
                case 1:
                    TextInfoPrivacyCell privacyCell = (TextInfoPrivacyCell) holder.itemView;
                    if (position != ChatRightsEditActivity.this.cantEditInfoRow) {
                        if (position == ChatRightsEditActivity.this.rankInfoRow) {
                            if (UserObject.isUserSelf(ChatRightsEditActivity.this.currentUser) && ChatRightsEditActivity.this.currentChat.creator) {
                                hint = LocaleController.getString("ChannelCreator", R.string.ChannelCreator);
                            } else {
                                hint = LocaleController.getString("ChannelAdmin", R.string.ChannelAdmin);
                            }
                            privacyCell.setText(LocaleController.formatString("EditAdminRankInfo", R.string.EditAdminRankInfo, hint));
                        }
                    } else {
                        privacyCell.setText(LocaleController.getString("EditAdminCantEdit", R.string.EditAdminCantEdit));
                    }
                    break;
                case 2:
                    TextSettingsCell actionCell = (TextSettingsCell) holder.itemView;
                    if (position != ChatRightsEditActivity.this.removeAdminRow) {
                        if (position == ChatRightsEditActivity.this.transferOwnerRow) {
                            actionCell.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
                            actionCell.setTag(Theme.key_windowBackgroundWhiteBlackText);
                            if (ChatRightsEditActivity.this.isChannel) {
                                actionCell.setText(LocaleController.getString("EditAdminChannelTransfer", R.string.EditAdminChannelTransfer), false);
                            } else {
                                actionCell.setText(LocaleController.getString("EditAdminGroupTransfer", R.string.EditAdminGroupTransfer), false);
                            }
                        }
                    } else {
                        actionCell.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText5));
                        actionCell.setTag(Theme.key_windowBackgroundWhiteRedText5);
                        if (ChatRightsEditActivity.this.currentType != 0) {
                            if (ChatRightsEditActivity.this.currentType == 1) {
                                actionCell.setText(LocaleController.getString("UserRestrictionsBlock", R.string.UserRestrictionsBlock), false);
                            }
                        } else {
                            actionCell.setText(LocaleController.getString("EditAdminRemoveAdmin", R.string.EditAdminRemoveAdmin), false);
                        }
                    }
                    break;
                case 3:
                    HeaderCell headerCell = (HeaderCell) holder.itemView;
                    if (position == 2) {
                        if (ChatRightsEditActivity.this.currentType != 0) {
                            if (ChatRightsEditActivity.this.currentType == 1) {
                                headerCell.setText(LocaleController.getString("UserRestrictionsCanDo", R.string.UserRestrictionsCanDo));
                            }
                        } else {
                            headerCell.setText(LocaleController.getString("EditAdminWhatCanDo", R.string.EditAdminWhatCanDo));
                        }
                    } else if (position == ChatRightsEditActivity.this.rankHeaderRow) {
                        headerCell.setText(LocaleController.getString("EditAdminRank", R.string.EditAdminRank));
                    }
                    break;
                case 4:
                    TextCheckCell2 checkCell = (TextCheckCell2) holder.itemView;
                    int i = ChatRightsEditActivity.this.changeInfoRow;
                    int i2 = R.drawable.permission_locked;
                    if (position == i) {
                        if (ChatRightsEditActivity.this.currentType == 0) {
                            if (ChatRightsEditActivity.this.isChannel) {
                                checkCell.setTextAndCheck(LocaleController.getString("EditAdminChangeChannelInfo", R.string.EditAdminChangeChannelInfo), ChatRightsEditActivity.this.adminRights.change_info, true);
                            } else {
                                checkCell.setTextAndCheck(LocaleController.getString("EditAdminChangeGroupInfo", R.string.EditAdminChangeGroupInfo), ChatRightsEditActivity.this.adminRights.change_info, true);
                            }
                        } else if (ChatRightsEditActivity.this.currentType == 1) {
                            checkCell.setTextAndCheck(LocaleController.getString("UserRestrictionsChangeInfo", R.string.UserRestrictionsChangeInfo), (ChatRightsEditActivity.this.bannedRights.change_info || ChatRightsEditActivity.this.defaultBannedRights.change_info) ? false : true, false);
                            if (!ChatRightsEditActivity.this.defaultBannedRights.change_info) {
                                i2 = 0;
                            }
                            checkCell.setIcon(i2);
                        }
                    } else if (position == ChatRightsEditActivity.this.postMessagesRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("EditAdminPostMessages", R.string.EditAdminPostMessages), ChatRightsEditActivity.this.adminRights.post_messages, true);
                    } else if (position == ChatRightsEditActivity.this.editMesagesRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("EditAdminEditMessages", R.string.EditAdminEditMessages), ChatRightsEditActivity.this.adminRights.edit_messages, true);
                    } else if (position == ChatRightsEditActivity.this.deleteMessagesRow) {
                        if (ChatRightsEditActivity.this.isChannel) {
                            checkCell.setTextAndCheck(LocaleController.getString("EditAdminDeleteMessages", R.string.EditAdminDeleteMessages), ChatRightsEditActivity.this.adminRights.delete_messages, true);
                        } else {
                            checkCell.setTextAndCheck(LocaleController.getString("EditAdminGroupDeleteMessages", R.string.EditAdminGroupDeleteMessages), ChatRightsEditActivity.this.adminRights.delete_messages, true);
                        }
                    } else if (position == ChatRightsEditActivity.this.addAdminsRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("EditAdminAddAdmins", R.string.EditAdminAddAdmins), ChatRightsEditActivity.this.adminRights.add_admins, false);
                    } else if (position == ChatRightsEditActivity.this.banUsersRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("EditAdminBanUsers", R.string.EditAdminBanUsers), ChatRightsEditActivity.this.adminRights.ban_users, true);
                    } else if (position == ChatRightsEditActivity.this.addUsersRow) {
                        if (ChatRightsEditActivity.this.currentType == 0) {
                            if (ChatObject.isActionBannedByDefault(ChatRightsEditActivity.this.currentChat, 3)) {
                                checkCell.setTextAndCheck(LocaleController.getString("EditAdminAddUsers", R.string.EditAdminAddUsers), ChatRightsEditActivity.this.adminRights.invite_users, true);
                            } else {
                                checkCell.setTextAndCheck(LocaleController.getString("EditAdminAddUsersViaLink", R.string.EditAdminAddUsersViaLink), ChatRightsEditActivity.this.adminRights.invite_users, true);
                            }
                        } else if (ChatRightsEditActivity.this.currentType == 1) {
                            checkCell.setTextAndCheck(LocaleController.getString("UserRestrictionsInviteUsers", R.string.UserRestrictionsInviteUsers), (ChatRightsEditActivity.this.bannedRights.invite_users || ChatRightsEditActivity.this.defaultBannedRights.invite_users) ? false : true, true);
                            if (!ChatRightsEditActivity.this.defaultBannedRights.invite_users) {
                                i2 = 0;
                            }
                            checkCell.setIcon(i2);
                        }
                    } else if (position == ChatRightsEditActivity.this.pinMessagesRow) {
                        if (ChatRightsEditActivity.this.currentType == 0) {
                            checkCell.setTextAndCheck(LocaleController.getString("EditAdminPinMessages", R.string.EditAdminPinMessages), ChatRightsEditActivity.this.adminRights.pin_messages, true);
                        } else if (ChatRightsEditActivity.this.currentType == 1) {
                            checkCell.setTextAndCheck(LocaleController.getString("UserRestrictionsPinMessages", R.string.UserRestrictionsPinMessages), (ChatRightsEditActivity.this.bannedRights.pin_messages || ChatRightsEditActivity.this.defaultBannedRights.pin_messages) ? false : true, true);
                            if (!ChatRightsEditActivity.this.defaultBannedRights.pin_messages) {
                                i2 = 0;
                            }
                            checkCell.setIcon(i2);
                        }
                    } else if (position == ChatRightsEditActivity.this.sendMessagesRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("UserRestrictionsSend", R.string.UserRestrictionsSend), (ChatRightsEditActivity.this.bannedRights.send_messages || ChatRightsEditActivity.this.defaultBannedRights.send_messages) ? false : true, true);
                        if (!ChatRightsEditActivity.this.defaultBannedRights.send_messages) {
                            i2 = 0;
                        }
                        checkCell.setIcon(i2);
                    } else if (position == ChatRightsEditActivity.this.sendMediaRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("UserRestrictionsSendMedia", R.string.UserRestrictionsSendMedia), (ChatRightsEditActivity.this.bannedRights.send_media || ChatRightsEditActivity.this.defaultBannedRights.send_media) ? false : true, true);
                        if (!ChatRightsEditActivity.this.defaultBannedRights.send_media) {
                            i2 = 0;
                        }
                        checkCell.setIcon(i2);
                    } else if (position == ChatRightsEditActivity.this.sendStickersRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("UserRestrictionsSendStickers", R.string.UserRestrictionsSendStickers), (ChatRightsEditActivity.this.bannedRights.send_stickers || ChatRightsEditActivity.this.defaultBannedRights.send_stickers) ? false : true, true);
                        if (!ChatRightsEditActivity.this.defaultBannedRights.send_stickers) {
                            i2 = 0;
                        }
                        checkCell.setIcon(i2);
                    } else if (position == ChatRightsEditActivity.this.embedLinksRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("UserRestrictionsEmbedLinks", R.string.UserRestrictionsEmbedLinks), (ChatRightsEditActivity.this.bannedRights.embed_links || ChatRightsEditActivity.this.defaultBannedRights.embed_links) ? false : true, true);
                        if (!ChatRightsEditActivity.this.defaultBannedRights.embed_links) {
                            i2 = 0;
                        }
                        checkCell.setIcon(i2);
                    } else if (position == ChatRightsEditActivity.this.sendPollsRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("UserRestrictionsSendPolls", R.string.UserRestrictionsSendPolls), (ChatRightsEditActivity.this.bannedRights.send_polls || ChatRightsEditActivity.this.defaultBannedRights.send_polls) ? false : true, true);
                        if (!ChatRightsEditActivity.this.defaultBannedRights.send_polls) {
                            i2 = 0;
                        }
                        checkCell.setIcon(i2);
                    }
                    if (position == ChatRightsEditActivity.this.sendMediaRow || position == ChatRightsEditActivity.this.sendStickersRow || position == ChatRightsEditActivity.this.embedLinksRow || position == ChatRightsEditActivity.this.sendPollsRow) {
                        if (!ChatRightsEditActivity.this.bannedRights.send_messages && !ChatRightsEditActivity.this.bannedRights.view_messages && !ChatRightsEditActivity.this.defaultBannedRights.send_messages && !ChatRightsEditActivity.this.defaultBannedRights.view_messages) {
                            z = true;
                        }
                        checkCell.setEnabled(z);
                    } else if (position == ChatRightsEditActivity.this.sendMessagesRow) {
                        if (!ChatRightsEditActivity.this.bannedRights.view_messages && !ChatRightsEditActivity.this.defaultBannedRights.view_messages) {
                            z = true;
                        }
                        checkCell.setEnabled(z);
                    }
                    break;
                case 5:
                    ShadowSectionCell shadowCell = (ShadowSectionCell) holder.itemView;
                    int i3 = ChatRightsEditActivity.this.rightsShadowRow;
                    int i4 = R.drawable.greydivider;
                    if (position != i3) {
                        if (position != ChatRightsEditActivity.this.removeAdminShadowRow) {
                            if (position == ChatRightsEditActivity.this.rankInfoRow) {
                                Context context = this.mContext;
                                if (!ChatRightsEditActivity.this.canEdit) {
                                    i4 = R.drawable.greydivider_bottom;
                                }
                                shadowCell.setBackgroundDrawable(Theme.getThemedDrawable(context, i4, Theme.key_windowBackgroundGrayShadow));
                            } else {
                                shadowCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                            }
                        } else {
                            shadowCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                        }
                    } else {
                        Context context2 = this.mContext;
                        if (ChatRightsEditActivity.this.removeAdminRow == -1 && ChatRightsEditActivity.this.rankRow == -1) {
                            i4 = R.drawable.greydivider_bottom;
                        }
                        shadowCell.setBackgroundDrawable(Theme.getThemedDrawable(context2, i4, Theme.key_windowBackgroundGrayShadow));
                    }
                    break;
                case 6:
                    TextDetailCell detailCell = (TextDetailCell) holder.itemView;
                    if (position == ChatRightsEditActivity.this.untilDateRow) {
                        if (ChatRightsEditActivity.this.bannedRights.until_date != 0 && Math.abs(((long) ChatRightsEditActivity.this.bannedRights.until_date) - (System.currentTimeMillis() / 1000)) <= 315360000) {
                            value = LocaleController.formatDateForBan(ChatRightsEditActivity.this.bannedRights.until_date);
                        } else {
                            value = LocaleController.getString("UserRestrictionsUntilForever", R.string.UserRestrictionsUntilForever);
                        }
                        detailCell.setTextAndValue(LocaleController.getString("UserRestrictionsDuration", R.string.UserRestrictionsDuration), value, false);
                    }
                    break;
                case 7:
                    PollEditTextCell textCell = (PollEditTextCell) holder.itemView;
                    if (UserObject.isUserSelf(ChatRightsEditActivity.this.currentUser) && ChatRightsEditActivity.this.currentChat.creator) {
                        hint2 = LocaleController.getString("ChannelCreator", R.string.ChannelCreator);
                    } else {
                        hint2 = LocaleController.getString("ChannelAdmin", R.string.ChannelAdmin);
                    }
                    this.ignoreTextChange = true;
                    textCell.getTextView().setEnabled(ChatRightsEditActivity.this.canEdit || ChatRightsEditActivity.this.currentChat.creator);
                    textCell.getTextView().setSingleLine(true);
                    textCell.getTextView().setImeOptions(6);
                    textCell.setTextAndHint(ChatRightsEditActivity.this.currentRank, hint2, false);
                    this.ignoreTextChange = false;
                    break;
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewAttachedToWindow(RecyclerView.ViewHolder holder) {
            if (holder.getAdapterPosition() == ChatRightsEditActivity.this.rankHeaderRow) {
                ChatRightsEditActivity.this.setTextLeft(holder.itemView);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewDetachedFromWindow(RecyclerView.ViewHolder holder) {
            if (holder.getAdapterPosition() == ChatRightsEditActivity.this.rankRow && ChatRightsEditActivity.this.getParentActivity() != null) {
                AndroidUtilities.hideKeyboard(ChatRightsEditActivity.this.getParentActivity().getCurrentFocus());
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == 0) {
                return 0;
            }
            if (position == 1 || position == ChatRightsEditActivity.this.rightsShadowRow || position == ChatRightsEditActivity.this.removeAdminShadowRow || position == ChatRightsEditActivity.this.untilSectionRow || position == ChatRightsEditActivity.this.transferOwnerShadowRow) {
                return 5;
            }
            if (position != 2 && position != ChatRightsEditActivity.this.rankHeaderRow) {
                if (position != ChatRightsEditActivity.this.changeInfoRow && position != ChatRightsEditActivity.this.postMessagesRow && position != ChatRightsEditActivity.this.editMesagesRow && position != ChatRightsEditActivity.this.deleteMessagesRow && position != ChatRightsEditActivity.this.addAdminsRow && position != ChatRightsEditActivity.this.banUsersRow && position != ChatRightsEditActivity.this.addUsersRow && position != ChatRightsEditActivity.this.pinMessagesRow && position != ChatRightsEditActivity.this.sendMessagesRow && position != ChatRightsEditActivity.this.sendMediaRow && position != ChatRightsEditActivity.this.sendStickersRow && position != ChatRightsEditActivity.this.embedLinksRow && position != ChatRightsEditActivity.this.sendPollsRow) {
                    if (position != ChatRightsEditActivity.this.cantEditInfoRow && position != ChatRightsEditActivity.this.rankInfoRow) {
                        if (position != ChatRightsEditActivity.this.untilDateRow) {
                            if (position != ChatRightsEditActivity.this.rankRow) {
                                return 2;
                            }
                            return 7;
                        }
                        return 6;
                    }
                    return 1;
                }
                return 4;
            }
            return 3;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatRightsEditActivity$TsKrS_JOK4f8ekfETZytjb_HasI
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$19$ChatRightsEditActivity();
            }
        };
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{UserCell2.class, TextSettingsCell.class, TextCheckCell2.class, HeaderCell.class, TextDetailCell.class, PollEditTextCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteRedText5), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayIcon), new ThemeDescription(this.listView, 0, new Class[]{TextDetailCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextDetailCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell2.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell2.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell2.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switch2Track), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell2.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switch2TrackChecked), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{HeaderCell.class}, new String[]{"textView2"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteRedText5), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{HeaderCell.class}, new String[]{"textView2"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText3), new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{PollEditTextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, ThemeDescription.FLAG_HINTTEXTCOLOR, new Class[]{PollEditTextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteHintText), new ThemeDescription(this.listView, 0, new Class[]{UserCell2.class}, new String[]{"nameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{UserCell2.class}, new String[]{"statusColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteGrayText), new ThemeDescription(this.listView, 0, new Class[]{UserCell2.class}, new String[]{"statusOnlineColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteBlueText), new ThemeDescription(this.listView, 0, new Class[]{UserCell2.class}, null, new Drawable[]{Theme.avatar_savedDrawable}, null, Theme.key_avatar_text), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundRed), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundOrange), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundViolet), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundGreen), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundCyan), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundBlue), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundPink), new ThemeDescription((View) null, 0, new Class[]{DialogRadioCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_dialogTextBlack), new ThemeDescription((View) null, 0, new Class[]{DialogRadioCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_dialogTextGray2), new ThemeDescription((View) null, ThemeDescription.FLAG_CHECKBOX, new Class[]{DialogRadioCell.class}, new String[]{"radioButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_dialogRadioBackground), new ThemeDescription((View) null, ThemeDescription.FLAG_CHECKBOXCHECK, new Class[]{DialogRadioCell.class}, new String[]{"radioButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_dialogRadioBackgroundChecked)};
    }

    public /* synthetic */ void lambda$getThemeDescriptions$19$ChatRightsEditActivity() {
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            int count = recyclerListView.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = this.listView.getChildAt(a);
                if (child instanceof UserCell2) {
                    ((UserCell2) child).update(0);
                }
            }
        }
    }
}
