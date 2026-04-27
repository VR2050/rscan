package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Shader;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.text.Spannable;
import android.text.method.LinkMovementMethod;
import android.text.style.CharacterStyle;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.PrivacyUsersActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.ChatMessageCell;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.RadioCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.HintView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hui.contacts.AddGroupingUserActivity;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PrivacyControlActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    public static final int PRIVACY_RULES_TYPE_ADDED_BY_PHONE = 7;
    public static final int PRIVACY_RULES_TYPE_CALLS = 2;
    public static final int PRIVACY_RULES_TYPE_FORWARDS = 5;
    public static final int PRIVACY_RULES_TYPE_INVITE = 1;
    public static final int PRIVACY_RULES_TYPE_LASTSEEN = 0;
    public static final int PRIVACY_RULES_TYPE_MOMENT = 8;
    public static final int PRIVACY_RULES_TYPE_P2P = 3;
    public static final int PRIVACY_RULES_TYPE_PHONE = 6;
    public static final int PRIVACY_RULES_TYPE_PHOTO = 4;
    private static final int done_button = 1;
    private final int DONE;
    private int alwaysShareRow;
    private ArrayList<Integer> currentMinus;
    private ArrayList<Integer> currentPlus;
    private int currentSubType;
    private int currentType;
    private int detailRow;
    private View doneButton;
    private boolean enableAnimation;
    private int everybodyRow;
    private ArrayList<Integer> initialMinus;
    private ArrayList<Integer> initialPlus;
    private int initialRulesSubType;
    private int initialRulesType;
    private int lastCheckedSubType;
    private int lastCheckedType;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private MessageCell messageCell;
    private int messageRow;
    private int myContactsRow;
    private int neverShareRow;
    private int nobodyRow;
    private int p2pDetailRow;
    private int p2pRow;
    private int p2pSectionRow;
    private int phoneContactsRow;
    private int phoneDetailRow;
    private int phoneEverybodyRow;
    private int phoneSectionRow;
    private int rowCount;
    private int rulesType;
    private int sectionRow;
    private int shareDetailRow;
    private int shareSectionRow;

    private static class LinkMovementMethodMy extends LinkMovementMethod {
        private LinkMovementMethodMy() {
        }

        @Override // android.text.method.LinkMovementMethod, android.text.method.ScrollingMovementMethod, android.text.method.BaseMovementMethod, android.text.method.MovementMethod
        public boolean onTouchEvent(TextView widget, Spannable buffer, MotionEvent event) {
            try {
                return super.onTouchEvent(widget, buffer, event);
            } catch (Exception e) {
                FileLog.e(e);
                return false;
            }
        }
    }

    private class MessageCell extends FrameLayout {
        private Drawable backgroundDrawable;
        private ChatMessageCell cell;
        private HintView hintView;
        private MessageObject messageObject;
        private Drawable shadowDrawable;

        public MessageCell(Context context) {
            super(context);
            setWillNotDraw(false);
            setClipToPadding(false);
            this.shadowDrawable = Theme.getThemedDrawable(context, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow);
            setPadding(0, AndroidUtilities.dp(11.0f), 0, AndroidUtilities.dp(11.0f));
            int date = ((int) (System.currentTimeMillis() / 1000)) - 3600;
            TLRPC.User currentUser = MessagesController.getInstance(PrivacyControlActivity.this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(PrivacyControlActivity.this.currentAccount).getClientUserId()));
            TLRPC.Message message = new TLRPC.TL_message();
            message.message = LocaleController.getString("PrivacyForwardsMessageLine", R.string.PrivacyForwardsMessageLine);
            message.date = date + 60;
            message.dialog_id = 1L;
            message.flags = 261;
            message.from_id = 0;
            message.id = 1;
            message.fwd_from = new TLRPC.TL_messageFwdHeader();
            message.fwd_from.from_name = ContactsController.formatName(currentUser.first_name, currentUser.last_name);
            message.media = new TLRPC.TL_messageMediaEmpty();
            message.out = false;
            message.to_id = new TLRPC.TL_peerUser();
            message.to_id.user_id = UserConfig.getInstance(PrivacyControlActivity.this.currentAccount).getClientUserId();
            MessageObject messageObject = new MessageObject(PrivacyControlActivity.this.currentAccount, message, true);
            this.messageObject = messageObject;
            messageObject.eventId = 1L;
            this.messageObject.resetLayout();
            ChatMessageCell chatMessageCell = new ChatMessageCell(context);
            this.cell = chatMessageCell;
            chatMessageCell.setDelegate(new ChatMessageCell.ChatMessageCellDelegate() { // from class: im.uwrkaxlmjj.ui.PrivacyControlActivity.MessageCell.1
                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ boolean canPerformActions() {
                    return ChatMessageCell.ChatMessageCellDelegate.CC.$default$canPerformActions(this);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didLongPress(ChatMessageCell chatMessageCell2, float f, float f2) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didLongPress(this, chatMessageCell2, f, f2);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didLongPressUserAvatar(ChatMessageCell chatMessageCell2, TLRPC.User user, float f, float f2) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didLongPressUserAvatar(this, chatMessageCell2, user, f, f2);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didPressBotButton(ChatMessageCell chatMessageCell2, TLRPC.KeyboardButton keyboardButton) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressBotButton(this, chatMessageCell2, keyboardButton);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didPressCancelSendButton(ChatMessageCell chatMessageCell2) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressCancelSendButton(this, chatMessageCell2);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didPressChannelAvatar(ChatMessageCell chatMessageCell2, TLRPC.Chat chat, int i, float f, float f2) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressChannelAvatar(this, chatMessageCell2, chat, i, f, f2);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didPressHiddenForward(ChatMessageCell chatMessageCell2) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressHiddenForward(this, chatMessageCell2);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didPressImage(ChatMessageCell chatMessageCell2, float f, float f2) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressImage(this, chatMessageCell2, f, f2);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didPressInstantButton(ChatMessageCell chatMessageCell2, int i) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressInstantButton(this, chatMessageCell2, i);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didPressOther(ChatMessageCell chatMessageCell2, float f, float f2) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressOther(this, chatMessageCell2, f, f2);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didPressReaction(ChatMessageCell chatMessageCell2, TLRPC.TL_reactionCount tL_reactionCount) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressReaction(this, chatMessageCell2, tL_reactionCount);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didPressRedpkgTransfer(ChatMessageCell chatMessageCell2, MessageObject messageObject2) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressRedpkgTransfer(this, chatMessageCell2, messageObject2);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didPressReplyMessage(ChatMessageCell chatMessageCell2, int i) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressReplyMessage(this, chatMessageCell2, i);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didPressShare(ChatMessageCell chatMessageCell2) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressShare(this, chatMessageCell2);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didPressSysNotifyVideoFullPlayer(ChatMessageCell chatMessageCell2) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressSysNotifyVideoFullPlayer(this, chatMessageCell2);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didPressUrl(ChatMessageCell chatMessageCell2, CharacterStyle characterStyle, boolean z) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressUrl(this, chatMessageCell2, characterStyle, z);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didPressUserAvatar(ChatMessageCell chatMessageCell2, TLRPC.User user, float f, float f2) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressUserAvatar(this, chatMessageCell2, user, f, f2);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didPressViaBot(ChatMessageCell chatMessageCell2, String str) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressViaBot(this, chatMessageCell2, str);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didPressVoteButton(ChatMessageCell chatMessageCell2, TLRPC.TL_pollAnswer tL_pollAnswer) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressVoteButton(this, chatMessageCell2, tL_pollAnswer);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void didStartVideoStream(MessageObject messageObject2) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$didStartVideoStream(this, messageObject2);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ String getAdminRank(int i) {
                    return ChatMessageCell.ChatMessageCellDelegate.CC.$default$getAdminRank(this, i);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void needOpenWebView(String str, String str2, String str3, String str4, int i, int i2) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$needOpenWebView(this, str, str2, str3, str4, i, i2);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ boolean needPlayMessage(MessageObject messageObject2) {
                    return ChatMessageCell.ChatMessageCellDelegate.CC.$default$needPlayMessage(this, messageObject2);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void setShouldNotRepeatSticker(MessageObject messageObject2) {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$setShouldNotRepeatSticker(this, messageObject2);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ boolean shouldRepeatSticker(MessageObject messageObject2) {
                    return ChatMessageCell.ChatMessageCellDelegate.CC.$default$shouldRepeatSticker(this, messageObject2);
                }

                @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                public /* synthetic */ void videoTimerReached() {
                    ChatMessageCell.ChatMessageCellDelegate.CC.$default$videoTimerReached(this);
                }
            });
            this.cell.isChat = false;
            this.cell.setFullyDraw(true);
            this.cell.setMessageObject(this.messageObject, null, false, false);
            addView(this.cell, LayoutHelper.createLinear(-1, -2));
            HintView hintView = new HintView(context, 1, true);
            this.hintView = hintView;
            addView(hintView, LayoutHelper.createFrame(-2.0f, -2.0f, 51, 19.0f, 0.0f, 19.0f, 0.0f));
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void dispatchDraw(Canvas canvas) {
            super.dispatchDraw(canvas);
            this.hintView.showForMessageCell(this.cell, false);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            Drawable newDrawable = Theme.getCachedWallpaperNonBlocking();
            if (newDrawable != null) {
                this.backgroundDrawable = newDrawable;
            }
            Drawable drawable = this.backgroundDrawable;
            if ((drawable instanceof ColorDrawable) || (drawable instanceof GradientDrawable)) {
                this.backgroundDrawable.setBounds(0, 0, getMeasuredWidth(), getMeasuredHeight());
                this.backgroundDrawable.draw(canvas);
            } else if (drawable instanceof BitmapDrawable) {
                BitmapDrawable bitmapDrawable = (BitmapDrawable) drawable;
                if (bitmapDrawable.getTileModeX() == Shader.TileMode.REPEAT) {
                    canvas.save();
                    float scale = 2.0f / AndroidUtilities.density;
                    canvas.scale(scale, scale);
                    this.backgroundDrawable.setBounds(0, 0, (int) Math.ceil(getMeasuredWidth() / scale), (int) Math.ceil(getMeasuredHeight() / scale));
                    this.backgroundDrawable.draw(canvas);
                    canvas.restore();
                } else {
                    int viewHeight = getMeasuredHeight();
                    float scaleX = getMeasuredWidth() / this.backgroundDrawable.getIntrinsicWidth();
                    float scaleY = viewHeight / this.backgroundDrawable.getIntrinsicHeight();
                    float scale2 = scaleX < scaleY ? scaleY : scaleX;
                    int width = (int) Math.ceil(this.backgroundDrawable.getIntrinsicWidth() * scale2);
                    int height = (int) Math.ceil(this.backgroundDrawable.getIntrinsicHeight() * scale2);
                    int x = (getMeasuredWidth() - width) / 2;
                    int y = (viewHeight - height) / 2;
                    canvas.save();
                    canvas.clipRect(0, 0, width, getMeasuredHeight());
                    this.backgroundDrawable.setBounds(x, y, x + width, y + height);
                    this.backgroundDrawable.draw(canvas);
                    canvas.restore();
                }
            } else {
                super.onDraw(canvas);
            }
            this.shadowDrawable.setBounds(0, 0, getMeasuredWidth(), getMeasuredHeight());
        }

        @Override // android.view.ViewGroup
        public boolean onInterceptTouchEvent(MotionEvent ev) {
            return false;
        }

        @Override // android.view.ViewGroup, android.view.View
        public boolean dispatchTouchEvent(MotionEvent ev) {
            return false;
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void dispatchSetPressed(boolean pressed) {
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return false;
        }

        @Override // android.view.View
        public void invalidate() {
            super.invalidate();
            this.cell.invalidate();
        }
    }

    public PrivacyControlActivity(int type) {
        this(type, false);
    }

    public PrivacyControlActivity(int type, boolean load) {
        this.initialPlus = new ArrayList<>();
        this.initialMinus = new ArrayList<>();
        this.lastCheckedType = -1;
        this.lastCheckedSubType = -1;
        this.DONE = 1;
        this.rulesType = type;
        if (load) {
            ContactsController.getInstance(this.currentAccount).loadPrivacySettings();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        checkPrivacy();
        updateRows();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.privacyRulesUpdated);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.emojiDidLoad);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.privacyRulesUpdated);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.emojiDidLoad);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        if (this.rulesType == 5) {
            this.messageCell = new MessageCell(context);
        }
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        int i = this.rulesType;
        if (i == 6) {
            this.actionBar.setTitle(LocaleController.getString("PrivacyPhone", R.string.PrivacyPhone));
        } else if (i == 5) {
            this.actionBar.setTitle(LocaleController.getString("PrivacyForwards", R.string.PrivacyForwards));
        } else if (i == 4) {
            this.actionBar.setTitle(LocaleController.getString("PrivacyProfilePhoto", R.string.PrivacyProfilePhoto));
        } else if (i == 3) {
            this.actionBar.setTitle(LocaleController.getString("PrivacyP2P", R.string.PrivacyP2P));
        } else if (i == 2) {
            this.actionBar.setTitle(LocaleController.getString("Calls", R.string.Calls));
        } else if (i == 1) {
            this.actionBar.setTitle(LocaleController.getString("GroupsAndChannels", R.string.GroupsAndChannels));
        } else if (i == 8) {
            this.actionBar.setTitle(LocaleController.getString("FriendHub", R.string.FriendHub));
        } else {
            this.actionBar.setTitle(LocaleController.getString("PrivacyLastSeen", R.string.PrivacyLastSeen));
        }
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.PrivacyControlActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    if (PrivacyControlActivity.this.checkDiscard()) {
                        PrivacyControlActivity.this.finishFragment();
                    }
                } else if (id == 1) {
                    PrivacyControlActivity.this.processDone();
                }
            }
        });
        View view = this.doneButton;
        int visibility = view != null ? view.getVisibility() : 8;
        ActionBarMenu menu = this.actionBar.createMenu();
        ActionBarMenuItem actionBarMenuItemAddItem = menu.addItem(1, LocaleController.getString("Done", R.string.Done));
        this.doneButton = actionBarMenuItemAddItem;
        actionBarMenuItemAddItem.setVisibility(visibility);
        this.listAdapter = new ListAdapter(context);
        this.fragmentView = new FrameLayout(context);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setLayoutManager(new LinearLayoutManager(context, 1, false));
        this.listView.setVerticalScrollBarEnabled(false);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f)));
        this.listView.setAdapter(this.listAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyControlActivity$yTisi86hdktGmRYoUYiLvgwbbB4
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view2, int i2) {
                this.f$0.lambda$createView$2$PrivacyControlActivity(view2, i2);
            }
        });
        setMessageText();
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$2$PrivacyControlActivity(View view, final int position) {
        ArrayList<Integer> createFromArray;
        if (position == this.nobodyRow || position == this.everybodyRow || position == this.myContactsRow) {
            int newType = this.currentType;
            if (position == this.nobodyRow) {
                newType = 1;
            } else if (position == this.everybodyRow) {
                newType = 0;
            } else if (position == this.myContactsRow) {
                newType = 2;
            }
            int i = this.currentType;
            if (newType == i) {
                return;
            }
            this.enableAnimation = true;
            this.lastCheckedType = i;
            this.currentType = newType;
            this.doneButton.setVisibility(hasChanges() ? 0 : 8);
            updateRows();
            return;
        }
        if (position == this.phoneContactsRow || position == this.phoneEverybodyRow) {
            int newType2 = this.currentSubType;
            if (position == this.phoneEverybodyRow) {
                newType2 = 0;
            } else if (position == this.phoneContactsRow) {
                newType2 = 1;
            }
            int i2 = this.currentSubType;
            if (newType2 == i2) {
                return;
            }
            this.enableAnimation = true;
            this.lastCheckedSubType = i2;
            this.currentSubType = newType2;
            this.doneButton.setVisibility(hasChanges() ? 0 : 8);
            updateRows();
            return;
        }
        if (position == this.neverShareRow || position == this.alwaysShareRow) {
            if (position == this.neverShareRow) {
                createFromArray = this.currentMinus;
            } else {
                createFromArray = this.currentPlus;
            }
            if (createFromArray.isEmpty()) {
                List<TLRPC.User> selectUsers = new ArrayList<>();
                AddGroupingUserActivity fragment = new AddGroupingUserActivity(selectUsers, 1, LocaleController.getString("EmpryUsersPlaceholder", R.string.EmpryUsersPlaceholder), false);
                fragment.setDelegate(new AddGroupingUserActivity.AddGroupingUserActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyControlActivity$BjRixbCLYiSWxiCGSJjvBRbGtvo
                    @Override // im.uwrkaxlmjj.ui.hui.contacts.AddGroupingUserActivity.AddGroupingUserActivityDelegate
                    public final void didSelectedContact(ArrayList arrayList) {
                        this.f$0.lambda$null$0$PrivacyControlActivity(position, arrayList);
                    }
                });
                presentFragment(fragment);
                return;
            }
            int i3 = this.rulesType;
            PrivacyUsersActivity fragment2 = new PrivacyUsersActivity(createFromArray, (i3 == 0 || i3 == 8) ? false : true, position == this.alwaysShareRow, this.rulesType, this.currentType, this.currentSubType);
            fragment2.setDelegate(new PrivacyUsersActivity.PrivacyActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyControlActivity$nKP-kbxaSmUSwB2lxuDD-5Ps1oM
                @Override // im.uwrkaxlmjj.ui.PrivacyUsersActivity.PrivacyActivityDelegate
                public final void didUpdateUserList(ArrayList arrayList, boolean z) {
                    this.f$0.lambda$null$1$PrivacyControlActivity(position, arrayList, z);
                }
            });
            presentFragment(fragment2);
            return;
        }
        if (position == this.p2pRow) {
            presentFragment(new PrivacyControlActivity(3));
        }
    }

    public /* synthetic */ void lambda$null$0$PrivacyControlActivity(int position, ArrayList users) {
        ArrayList<Integer> ids = new ArrayList<>();
        if (users != null && users.size() > 0) {
            Iterator it = users.iterator();
            while (it.hasNext()) {
                TLRPC.User user = (TLRPC.User) it.next();
                if (user != null && user.id > 0) {
                    ids.add(Integer.valueOf(user.id));
                }
            }
        }
        if (position == this.neverShareRow) {
            this.currentMinus = ids;
            for (int a = 0; a < this.currentMinus.size(); a++) {
                this.currentPlus.remove(this.currentMinus.get(a));
            }
        } else {
            this.currentPlus = ids;
            for (int a2 = 0; a2 < this.currentPlus.size(); a2++) {
                this.currentMinus.remove(this.currentPlus.get(a2));
            }
        }
        this.lastCheckedType = -1;
        this.doneButton.setVisibility(hasChanges() ? 0 : 8);
        this.listAdapter.notifyDataSetChanged();
    }

    public /* synthetic */ void lambda$null$1$PrivacyControlActivity(int position, ArrayList ids, boolean added) {
        if (position == this.neverShareRow) {
            this.currentMinus = ids;
            if (added) {
                for (int a = 0; a < this.currentMinus.size(); a++) {
                    this.currentPlus.remove(this.currentMinus.get(a));
                }
            }
        } else {
            this.currentPlus = ids;
            if (added) {
                for (int a2 = 0; a2 < this.currentPlus.size(); a2++) {
                    this.currentMinus.remove(this.currentPlus.get(a2));
                }
            }
        }
        this.doneButton.setVisibility(hasChanges() ? 0 : 8);
        this.listAdapter.notifyDataSetChanged();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.privacyRulesUpdated) {
            checkPrivacy();
        } else if (id == NotificationCenter.emojiDidLoad) {
            this.listView.invalidateViews();
        }
    }

    private void applyCurrentPrivacySettings() {
        TLRPC.InputUser inputUser;
        TLRPC.InputUser inputUser2;
        TLRPC.TL_account_setPrivacy req = new TLRPC.TL_account_setPrivacy();
        int i = this.rulesType;
        if (i == 6) {
            req.key = new TLRPC.TL_inputPrivacyKeyPhoneNumber();
            if (this.currentType == 1) {
                TLRPC.TL_account_setPrivacy req2 = new TLRPC.TL_account_setPrivacy();
                req2.key = new TLRPC.TL_inputPrivacyKeyAddedByPhone();
                if (this.currentSubType == 0) {
                    req2.rules.add(new TLRPC.TL_inputPrivacyValueAllowAll());
                } else {
                    req2.rules.add(new TLRPC.TL_inputPrivacyValueAllowContacts());
                }
                ConnectionsManager.getInstance(this.currentAccount).sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyControlActivity$fMa3-M9ZwPTZiHaYvkk1ONGQcFk
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$applyCurrentPrivacySettings$4$PrivacyControlActivity(tLObject, tL_error);
                    }
                }, 2);
            }
        } else if (i == 5) {
            req.key = new TLRPC.TL_inputPrivacyKeyForwards();
        } else if (i == 4) {
            req.key = new TLRPC.TL_inputPrivacyKeyProfilePhoto();
        } else if (i == 3) {
            req.key = new TLRPC.TL_inputPrivacyKeyPhoneP2P();
        } else if (i == 2) {
            req.key = new TLRPC.TL_inputPrivacyKeyPhoneCall();
        } else if (i == 1) {
            req.key = new TLRPC.TL_inputPrivacyKeyChatInvite();
        } else if (i == 8) {
            req.key = new TLRPC.TL_inputPrivacyKeyMoment();
        } else {
            req.key = new TLRPC.TL_inputPrivacyKeyStatusTimestamp();
        }
        if (this.currentType != 0 && this.currentPlus.size() > 0) {
            TLRPC.TL_inputPrivacyValueAllowUsers usersRule = new TLRPC.TL_inputPrivacyValueAllowUsers();
            TLRPC.TL_inputPrivacyValueAllowChatParticipants chatsRule = new TLRPC.TL_inputPrivacyValueAllowChatParticipants();
            for (int a = 0; a < this.currentPlus.size(); a++) {
                int id = this.currentPlus.get(a).intValue();
                if (id > 0) {
                    TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(id));
                    if (user != null && (inputUser2 = MessagesController.getInstance(this.currentAccount).getInputUser(user)) != null) {
                        usersRule.users.add(inputUser2);
                    }
                } else {
                    chatsRule.chats.add(Integer.valueOf(-id));
                }
            }
            req.rules.add(usersRule);
            req.rules.add(chatsRule);
        }
        if (this.currentType != 1 && this.currentMinus.size() > 0) {
            TLRPC.TL_inputPrivacyValueDisallowUsers usersRule2 = new TLRPC.TL_inputPrivacyValueDisallowUsers();
            TLRPC.TL_inputPrivacyValueDisallowChatParticipants chatsRule2 = new TLRPC.TL_inputPrivacyValueDisallowChatParticipants();
            for (int a2 = 0; a2 < this.currentMinus.size(); a2++) {
                int id2 = this.currentMinus.get(a2).intValue();
                if (id2 > 0) {
                    TLRPC.User user2 = getMessagesController().getUser(Integer.valueOf(id2));
                    if (user2 != null && (inputUser = getMessagesController().getInputUser(user2)) != null) {
                        usersRule2.users.add(inputUser);
                    }
                } else {
                    chatsRule2.chats.add(Integer.valueOf(-id2));
                }
            }
            req.rules.add(usersRule2);
            req.rules.add(chatsRule2);
        }
        int i2 = this.currentType;
        if (i2 == 0) {
            req.rules.add(new TLRPC.TL_inputPrivacyValueAllowAll());
        } else if (i2 == 1) {
            req.rules.add(new TLRPC.TL_inputPrivacyValueDisallowAll());
        } else if (i2 == 2) {
            req.rules.add(new TLRPC.TL_inputPrivacyValueAllowContacts());
        }
        AlertDialog progressDialog = null;
        if (getParentActivity() != null) {
            progressDialog = new AlertDialog(getParentActivity(), 3);
            progressDialog.setCanCancel(false);
            progressDialog.show();
        }
        final AlertDialog progressDialogFinal = progressDialog;
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyControlActivity$0_IC84Q1dvqwLeykIwumVcvPWGA
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$applyCurrentPrivacySettings$6$PrivacyControlActivity(progressDialogFinal, tLObject, tL_error);
            }
        }, 2);
    }

    public /* synthetic */ void lambda$applyCurrentPrivacySettings$4$PrivacyControlActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyControlActivity$9PF6LRZDAwUhZbfuNNSIsdASntY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$3$PrivacyControlActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$3$PrivacyControlActivity(TLRPC.TL_error error, TLObject response) {
        if (error == null) {
            TLRPC.TL_account_privacyRules privacyRules = (TLRPC.TL_account_privacyRules) response;
            ContactsController.getInstance(this.currentAccount).setPrivacyRules(privacyRules.rules, 7);
        }
    }

    public /* synthetic */ void lambda$applyCurrentPrivacySettings$6$PrivacyControlActivity(final AlertDialog progressDialogFinal, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyControlActivity$TIsRFm3Lk5myruYwn80KX1-OEd8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$5$PrivacyControlActivity(progressDialogFinal, error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$5$PrivacyControlActivity(AlertDialog progressDialogFinal, TLRPC.TL_error error, TLObject response) {
        if (progressDialogFinal != null) {
            try {
                progressDialogFinal.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        if (error == null) {
            TLRPC.TL_account_privacyRules privacyRules = (TLRPC.TL_account_privacyRules) response;
            MessagesController.getInstance(this.currentAccount).putUsers(privacyRules.users, false);
            MessagesController.getInstance(this.currentAccount).putChats(privacyRules.chats, false);
            ContactsController.getInstance(this.currentAccount).setPrivacyRules(privacyRules.rules, this.rulesType);
            finishFragment();
            return;
        }
        showErrorAlert();
    }

    private void showErrorAlert() {
        if (getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setMessage(LocaleController.getString("PrivacyFloodControlError", R.string.PrivacyFloodControlError));
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        showDialog(builder.create());
    }

    private void checkPrivacy() {
        this.currentPlus = new ArrayList<>();
        this.currentMinus = new ArrayList<>();
        ArrayList<TLRPC.PrivacyRule> privacyRules = ContactsController.getInstance(this.currentAccount).getPrivacyRules(this.rulesType);
        if (privacyRules == null || privacyRules.size() == 0) {
            this.currentType = 1;
        } else {
            int type = -1;
            for (int a = 0; a < privacyRules.size(); a++) {
                TLRPC.PrivacyRule rule = privacyRules.get(a);
                if (rule instanceof TLRPC.TL_privacyValueAllowChatParticipants) {
                    TLRPC.TL_privacyValueAllowChatParticipants privacyValueAllowChatParticipants = (TLRPC.TL_privacyValueAllowChatParticipants) rule;
                    int N = privacyValueAllowChatParticipants.chats.size();
                    for (int b = 0; b < N; b++) {
                        this.currentPlus.add(Integer.valueOf(-privacyValueAllowChatParticipants.chats.get(b).intValue()));
                    }
                } else if (rule instanceof TLRPC.TL_privacyValueDisallowChatParticipants) {
                    TLRPC.TL_privacyValueDisallowChatParticipants privacyValueDisallowChatParticipants = (TLRPC.TL_privacyValueDisallowChatParticipants) rule;
                    int N2 = privacyValueDisallowChatParticipants.chats.size();
                    for (int b2 = 0; b2 < N2; b2++) {
                        this.currentMinus.add(Integer.valueOf(-privacyValueDisallowChatParticipants.chats.get(b2).intValue()));
                    }
                } else if (rule instanceof TLRPC.TL_privacyValueAllowUsers) {
                    TLRPC.TL_privacyValueAllowUsers privacyValueAllowUsers = (TLRPC.TL_privacyValueAllowUsers) rule;
                    this.currentPlus.addAll(privacyValueAllowUsers.users);
                } else if (rule instanceof TLRPC.TL_privacyValueDisallowUsers) {
                    TLRPC.TL_privacyValueDisallowUsers privacyValueDisallowUsers = (TLRPC.TL_privacyValueDisallowUsers) rule;
                    this.currentMinus.addAll(privacyValueDisallowUsers.users);
                } else if (type == -1) {
                    if (rule instanceof TLRPC.TL_privacyValueAllowAll) {
                        type = 0;
                    } else if (rule instanceof TLRPC.TL_privacyValueDisallowAll) {
                        type = 1;
                    } else {
                        type = 2;
                    }
                }
            }
            if (type == 0 || (type == -1 && this.currentMinus.size() > 0)) {
                this.currentType = 0;
            } else if (type == 2 || (type == -1 && this.currentMinus.size() > 0 && this.currentPlus.size() > 0)) {
                this.currentType = 2;
            } else if (type == 1 || (type == -1 && this.currentPlus.size() > 0)) {
                this.currentType = 1;
            }
            View view = this.doneButton;
            if (view != null) {
                view.setVisibility(8);
            }
        }
        this.initialPlus.clear();
        this.initialMinus.clear();
        this.initialRulesType = this.currentType;
        this.initialPlus.addAll(this.currentPlus);
        this.initialMinus.addAll(this.currentMinus);
        if (this.rulesType == 6) {
            ArrayList<TLRPC.PrivacyRule> privacyRules2 = ContactsController.getInstance(this.currentAccount).getPrivacyRules(7);
            if (privacyRules2 == null || privacyRules2.size() == 0) {
                this.currentSubType = 0;
            } else {
                int a2 = 0;
                while (true) {
                    if (a2 >= privacyRules2.size()) {
                        break;
                    }
                    TLRPC.PrivacyRule rule2 = privacyRules2.get(a2);
                    if (rule2 instanceof TLRPC.TL_privacyValueAllowAll) {
                        this.currentSubType = 0;
                        break;
                    } else if (rule2 instanceof TLRPC.TL_privacyValueDisallowAll) {
                        this.currentSubType = 2;
                        break;
                    } else if (!(rule2 instanceof TLRPC.TL_privacyValueAllowContacts)) {
                        a2++;
                    } else {
                        this.currentSubType = 1;
                        break;
                    }
                }
            }
            this.initialRulesSubType = this.currentSubType;
        }
        updateRows();
    }

    private boolean hasChanges() {
        int i = this.initialRulesType;
        int i2 = this.currentType;
        if (i != i2) {
            return true;
        }
        if ((this.rulesType == 6 && i2 == 1 && this.initialRulesSubType != this.currentSubType) || this.initialMinus.size() != this.currentMinus.size() || this.initialPlus.size() != this.currentPlus.size()) {
            return true;
        }
        Collections.sort(this.initialPlus);
        Collections.sort(this.currentPlus);
        if (!this.initialPlus.equals(this.currentPlus)) {
            return true;
        }
        Collections.sort(this.initialMinus);
        Collections.sort(this.currentMinus);
        return !this.initialMinus.equals(this.currentMinus);
    }

    private void updateRows() {
        this.rowCount = 0;
        if (this.rulesType == 5) {
            this.rowCount = 0 + 1;
            this.messageRow = 0;
        } else {
            this.messageRow = -1;
        }
        int i = this.rowCount;
        int i2 = i + 1;
        this.rowCount = i2;
        this.sectionRow = i;
        int i3 = i2 + 1;
        this.rowCount = i3;
        this.everybodyRow = i2;
        this.rowCount = i3 + 1;
        this.myContactsRow = i3;
        int i4 = this.rulesType;
        if (i4 != 0 && i4 != 2 && i4 != 3 && i4 != 5 && i4 != 6 && i4 != 8) {
            this.nobodyRow = -1;
        } else {
            int i5 = this.rowCount;
            this.rowCount = i5 + 1;
            this.nobodyRow = i5;
        }
        if (this.rulesType == 6 && this.currentType == 1) {
            int i6 = this.rowCount;
            int i7 = i6 + 1;
            this.rowCount = i7;
            this.phoneDetailRow = i6;
            int i8 = i7 + 1;
            this.rowCount = i8;
            this.phoneSectionRow = i7;
            int i9 = i8 + 1;
            this.rowCount = i9;
            this.phoneEverybodyRow = i8;
            this.rowCount = i9 + 1;
            this.phoneContactsRow = i9;
        } else {
            this.phoneDetailRow = -1;
            this.phoneSectionRow = -1;
            this.phoneEverybodyRow = -1;
            this.phoneContactsRow = -1;
        }
        int i10 = this.rowCount;
        int i11 = i10 + 1;
        this.rowCount = i11;
        this.detailRow = i10;
        this.rowCount = i11 + 1;
        this.shareSectionRow = i11;
        int i12 = this.currentType;
        if (i12 == 1 || i12 == 2) {
            int i13 = this.rowCount;
            this.rowCount = i13 + 1;
            this.alwaysShareRow = i13;
        } else {
            this.alwaysShareRow = -1;
        }
        int i14 = this.currentType;
        if (i14 == 0 || i14 == 2) {
            int i15 = this.rowCount;
            this.rowCount = i15 + 1;
            this.neverShareRow = i15;
        } else {
            this.neverShareRow = -1;
        }
        int i16 = this.rowCount;
        int i17 = i16 + 1;
        this.rowCount = i17;
        this.shareDetailRow = i16;
        if (this.rulesType == 2) {
            int i18 = i17 + 1;
            this.rowCount = i18;
            this.p2pSectionRow = i17;
            int i19 = i18 + 1;
            this.rowCount = i19;
            this.p2pRow = i18;
            this.rowCount = i19 + 1;
            this.p2pDetailRow = i19;
        } else {
            this.p2pSectionRow = -1;
            this.p2pRow = -1;
            this.p2pDetailRow = -1;
        }
        setMessageText();
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private void setMessageText() {
        MessageCell messageCell = this.messageCell;
        if (messageCell != null) {
            int i = this.currentType;
            if (i == 0) {
                messageCell.hintView.setOverrideText(LocaleController.getString("PrivacyForwardsEverybody", R.string.PrivacyForwardsEverybody));
                this.messageCell.messageObject.messageOwner.fwd_from.from_id = 1;
            } else if (i == 1) {
                messageCell.hintView.setOverrideText(LocaleController.getString("PrivacyForwardsNobody", R.string.PrivacyForwardsNobody));
                this.messageCell.messageObject.messageOwner.fwd_from.from_id = 0;
            } else {
                messageCell.hintView.setOverrideText(LocaleController.getString("PrivacyForwardsContacts", R.string.PrivacyForwardsContacts));
                this.messageCell.messageObject.messageOwner.fwd_from.from_id = 1;
            }
            this.messageCell.cell.forceResetMessageObject();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        this.lastCheckedType = -1;
        this.lastCheckedSubType = -1;
        this.enableAnimation = false;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        return checkDiscard();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processDone() {
        if (getParentActivity() == null) {
            return;
        }
        if (this.currentType != 0 && this.rulesType == 0) {
            final SharedPreferences preferences = MessagesController.getGlobalMainSettings();
            boolean showed = preferences.getBoolean("privacyAlertShowed", false);
            if (!showed) {
                AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                if (this.rulesType == 1) {
                    builder.setMessage(LocaleController.getString("WhoCanAddMeInfo", R.string.WhoCanAddMeInfo));
                } else {
                    builder.setMessage(LocaleController.getString("CustomHelp", R.string.CustomHelp));
                }
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyControlActivity$lkoAQETgANJvp4xQkUiaeDDXQ_U
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$processDone$7$PrivacyControlActivity(preferences, dialogInterface, i);
                    }
                });
                builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                showDialog(builder.create());
                return;
            }
        }
        applyCurrentPrivacySettings();
    }

    public /* synthetic */ void lambda$processDone$7$PrivacyControlActivity(SharedPreferences preferences, DialogInterface dialogInterface, int i) {
        applyCurrentPrivacySettings();
        preferences.edit().putBoolean("privacyAlertShowed", true).commit();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean checkDiscard() {
        if (this.doneButton.getVisibility() == 0) {
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setTitle(LocaleController.getString("UserRestrictionsApplyChanges", R.string.UserRestrictionsApplyChanges));
            builder.setMessage(LocaleController.getString("PrivacySettingsChangedAlert", R.string.PrivacySettingsChangedAlert));
            builder.setPositiveButton(LocaleController.getString("ApplyTheme", R.string.ApplyTheme), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyControlActivity$KzjFihM8-0k01pqWN6jt2wh49yE
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$checkDiscard$8$PrivacyControlActivity(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("PassportDiscard", R.string.PassportDiscard), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyControlActivity$PLrO4xrWCLRX-J5ZofueCtK4WmY
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$checkDiscard$9$PrivacyControlActivity(dialogInterface, i);
                }
            });
            showDialog(builder.create());
            return false;
        }
        return true;
    }

    public /* synthetic */ void lambda$checkDiscard$8$PrivacyControlActivity(DialogInterface dialogInterface, int i) {
        processDone();
    }

    public /* synthetic */ void lambda$checkDiscard$9$PrivacyControlActivity(DialogInterface dialog, int which) {
        finishFragment();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean canBeginSlide() {
        return checkDiscard();
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int position = holder.getAdapterPosition();
            return position == PrivacyControlActivity.this.nobodyRow || position == PrivacyControlActivity.this.everybodyRow || position == PrivacyControlActivity.this.myContactsRow || position == PrivacyControlActivity.this.neverShareRow || position == PrivacyControlActivity.this.alwaysShareRow || (position == PrivacyControlActivity.this.p2pRow && !ContactsController.getInstance(PrivacyControlActivity.this.currentAccount).getLoadingPrivicyInfo(3));
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return PrivacyControlActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                View view2 = new TextSettingsCell(this.mContext);
                view2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                view = view2;
            } else if (viewType == 1) {
                view = new TextInfoPrivacyCell(this.mContext);
            } else if (viewType == 2) {
                View view3 = new HeaderCell(this.mContext);
                view3.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                view = view3;
            } else if (viewType == 3) {
                View view4 = new RadioCell(this.mContext);
                view4.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                view = view4;
            } else if (viewType == 4) {
                view = PrivacyControlActivity.this.messageCell;
            } else {
                view = new ShadowSectionCell(this.mContext);
                view.setBackgroundColor(0);
            }
            return new RecyclerListView.Holder(view);
        }

        private int getUsersCount(ArrayList<Integer> arrayList) {
            int count = 0;
            for (int a = 0; a < arrayList.size(); a++) {
                int id = arrayList.get(a).intValue();
                if (id <= 0) {
                    TLRPC.Chat chat = PrivacyControlActivity.this.getMessagesController().getChat(Integer.valueOf(-id));
                    if (chat != null) {
                        count += chat.participants_count;
                    }
                } else {
                    count++;
                }
            }
            return count;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String value;
            String value2;
            String value3;
            int i;
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                TextSettingsCell textCell = (TextSettingsCell) holder.itemView;
                textCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                if (position == PrivacyControlActivity.this.alwaysShareRow) {
                    if (PrivacyControlActivity.this.currentPlus.size() != 0) {
                        value3 = LocaleController.formatPluralString("Users", getUsersCount(PrivacyControlActivity.this.currentPlus));
                    } else {
                        value3 = LocaleController.getString("EmpryUsersPlaceholder", R.string.EmpryUsersPlaceholder);
                    }
                    if (PrivacyControlActivity.this.rulesType == 0 || PrivacyControlActivity.this.rulesType == 8) {
                        i = -1;
                        textCell.setTextAndValue(LocaleController.getString("AlwaysShareWith", R.string.AlwaysShareWith), value3, PrivacyControlActivity.this.neverShareRow != -1);
                    } else {
                        textCell.setTextAndValue(LocaleController.getString("AlwaysAllow", R.string.AlwaysAllow), value3, PrivacyControlActivity.this.neverShareRow != -1);
                        i = -1;
                    }
                    if (PrivacyControlActivity.this.neverShareRow != i) {
                        textCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                        return;
                    }
                    return;
                }
                if (position == PrivacyControlActivity.this.neverShareRow) {
                    if (PrivacyControlActivity.this.currentMinus.size() != 0) {
                        value2 = LocaleController.formatPluralString("Users", getUsersCount(PrivacyControlActivity.this.currentMinus));
                    } else {
                        value2 = LocaleController.getString("EmpryUsersPlaceholder", R.string.EmpryUsersPlaceholder);
                    }
                    if (PrivacyControlActivity.this.rulesType == 0 || PrivacyControlActivity.this.rulesType == 8) {
                        textCell.setTextAndValue(LocaleController.getString("NeverShareWith", R.string.NeverShareWith), value2, false);
                        return;
                    } else {
                        textCell.setTextAndValue(LocaleController.getString("NeverAllow", R.string.NeverAllow), value2, false);
                        return;
                    }
                }
                if (position == PrivacyControlActivity.this.p2pRow) {
                    if (ContactsController.getInstance(PrivacyControlActivity.this.currentAccount).getLoadingPrivicyInfo(3)) {
                        value = LocaleController.getString("Loading", R.string.Loading);
                    } else {
                        value = PrivacySettingsActivity.formatRulesString(PrivacyControlActivity.this.getAccountInstance(), 3);
                    }
                    textCell.setTextAndValue(LocaleController.getString("PrivacyP2P2", R.string.PrivacyP2P2), value, false);
                    return;
                }
                return;
            }
            if (itemViewType == 1) {
                TextInfoPrivacyCell privacyCell = (TextInfoPrivacyCell) holder.itemView;
                if (position == PrivacyControlActivity.this.detailRow) {
                    if (PrivacyControlActivity.this.rulesType == 6) {
                        if (PrivacyControlActivity.this.currentType == 1 && PrivacyControlActivity.this.currentSubType == 1) {
                            privacyCell.setText(LocaleController.getString("PrivacyPhoneInfo3", R.string.PrivacyPhoneInfo3));
                            return;
                        } else {
                            privacyCell.setText(LocaleController.getString("PrivacyPhoneInfo", R.string.PrivacyPhoneInfo));
                            return;
                        }
                    }
                    if (PrivacyControlActivity.this.rulesType != 5) {
                        if (PrivacyControlActivity.this.rulesType != 4) {
                            if (PrivacyControlActivity.this.rulesType != 3) {
                                if (PrivacyControlActivity.this.rulesType != 2) {
                                    if (PrivacyControlActivity.this.rulesType != 1) {
                                        if (PrivacyControlActivity.this.rulesType == 8) {
                                            privacyCell.setText(LocaleController.getString("PrivacyExceptions", R.string.PrivacyExceptions));
                                            return;
                                        } else {
                                            privacyCell.setText(LocaleController.getString("CustomHelp", R.string.CustomHelp));
                                            return;
                                        }
                                    }
                                    privacyCell.setText(LocaleController.getString("WhoCanAddMeInfo", R.string.WhoCanAddMeInfo));
                                    return;
                                }
                                privacyCell.setText(LocaleController.getString("WhoCanCallMeInfo", R.string.WhoCanCallMeInfo));
                                return;
                            }
                            privacyCell.setText(LocaleController.getString("PrivacyCallsP2PHelp", R.string.PrivacyCallsP2PHelp));
                            return;
                        }
                        privacyCell.setText(LocaleController.getString("PrivacyProfilePhotoInfo", R.string.PrivacyProfilePhotoInfo));
                        return;
                    }
                    privacyCell.setText(LocaleController.getString("PrivacyForwardsInfo", R.string.PrivacyForwardsInfo));
                    return;
                }
                if (position == PrivacyControlActivity.this.shareDetailRow) {
                    if (PrivacyControlActivity.this.rulesType != 6) {
                        if (PrivacyControlActivity.this.rulesType != 5) {
                            if (PrivacyControlActivity.this.rulesType != 4) {
                                if (PrivacyControlActivity.this.rulesType != 3) {
                                    if (PrivacyControlActivity.this.rulesType != 2) {
                                        if (PrivacyControlActivity.this.rulesType == 1) {
                                            privacyCell.setText(LocaleController.getString("CustomShareInfo", R.string.CustomShareInfo));
                                            return;
                                        } else {
                                            privacyCell.setText(LocaleController.getString("CustomShareSettingsHelp", R.string.CustomShareSettingsHelp));
                                            return;
                                        }
                                    }
                                    privacyCell.setText(LocaleController.getString("CustomCallInfo", R.string.CustomCallInfo));
                                    return;
                                }
                                privacyCell.setText(LocaleController.getString("CustomP2PInfo", R.string.CustomP2PInfo));
                                return;
                            }
                            privacyCell.setText(LocaleController.getString("PrivacyProfilePhotoInfo2", R.string.PrivacyProfilePhotoInfo2));
                            return;
                        }
                        privacyCell.setText(LocaleController.getString("PrivacyForwardsInfo2", R.string.PrivacyForwardsInfo2));
                        return;
                    }
                    privacyCell.setText(LocaleController.getString("PrivacyPhoneInfo2", R.string.PrivacyPhoneInfo2));
                    return;
                }
                int unused = PrivacyControlActivity.this.p2pDetailRow;
                return;
            }
            if (itemViewType == 2) {
                HeaderCell headerCell = (HeaderCell) holder.itemView;
                if (position == PrivacyControlActivity.this.sectionRow) {
                    if (PrivacyControlActivity.this.rulesType != 6) {
                        if (PrivacyControlActivity.this.rulesType != 5) {
                            if (PrivacyControlActivity.this.rulesType != 4) {
                                if (PrivacyControlActivity.this.rulesType != 3) {
                                    if (PrivacyControlActivity.this.rulesType != 2) {
                                        if (PrivacyControlActivity.this.rulesType != 1) {
                                            if (PrivacyControlActivity.this.rulesType == 8) {
                                                headerCell.setText(LocaleController.getString("WhoCanViewMoment", R.string.WhoCanViewMoment));
                                            } else {
                                                headerCell.setText(LocaleController.getString("LastSeenTitle", R.string.LastSeenTitle));
                                            }
                                        } else {
                                            headerCell.setText(LocaleController.getString("WhoCanAddMe", R.string.WhoCanAddMe));
                                        }
                                    } else {
                                        headerCell.setText(LocaleController.getString("WhoCanCallMe", R.string.WhoCanCallMe));
                                    }
                                } else {
                                    headerCell.setText(LocaleController.getString("P2PEnabledWith", R.string.P2PEnabledWith));
                                }
                            } else {
                                headerCell.setText(LocaleController.getString("PrivacyProfilePhotoTitle", R.string.PrivacyProfilePhotoTitle));
                            }
                        } else {
                            headerCell.setText(LocaleController.getString("PrivacyForwardsTitle", R.string.PrivacyForwardsTitle));
                        }
                    } else {
                        headerCell.setText(LocaleController.getString("PrivacyPhoneTitle", R.string.PrivacyPhoneTitle));
                    }
                } else if (position != PrivacyControlActivity.this.shareSectionRow) {
                    if (position != PrivacyControlActivity.this.p2pSectionRow) {
                        if (position == PrivacyControlActivity.this.phoneSectionRow) {
                            headerCell.setText(LocaleController.getString("PrivacyPhoneTitle2", R.string.PrivacyPhoneTitle2));
                        }
                    } else {
                        headerCell.setText(LocaleController.getString("PrivacyP2PHeader", R.string.PrivacyP2PHeader));
                    }
                } else {
                    headerCell.setText(LocaleController.getString("AddExceptions", R.string.AddExceptions));
                }
                headerCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                return;
            }
            if (itemViewType == 3) {
                RadioCell radioCell = (RadioCell) holder.itemView;
                if (position == PrivacyControlActivity.this.everybodyRow || position == PrivacyControlActivity.this.myContactsRow || position == PrivacyControlActivity.this.nobodyRow) {
                    int checkedType = 0;
                    if (position == PrivacyControlActivity.this.everybodyRow) {
                        if (PrivacyControlActivity.this.rulesType == 3) {
                            radioCell.setText(LocaleController.getString("P2PEverybody", R.string.P2PEverybody), PrivacyControlActivity.this.lastCheckedType == 0, true);
                        } else {
                            radioCell.setText(LocaleController.getString("LastSeenEverybody", R.string.LastSeenEverybody), PrivacyControlActivity.this.lastCheckedType == 0, true);
                        }
                        checkedType = 0;
                    } else if (position == PrivacyControlActivity.this.myContactsRow) {
                        if (PrivacyControlActivity.this.rulesType == 3) {
                            radioCell.setText(LocaleController.getString("P2PContacts", R.string.P2PContacts), PrivacyControlActivity.this.lastCheckedType == 2, PrivacyControlActivity.this.nobodyRow != -1);
                        } else {
                            radioCell.setText(LocaleController.getString("LastSeenContacts", R.string.LastSeenContacts), PrivacyControlActivity.this.lastCheckedType == 2, PrivacyControlActivity.this.nobodyRow != -1);
                        }
                        checkedType = 2;
                        if (PrivacyControlActivity.this.nobodyRow == -1) {
                            radioCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                        } else {
                            radioCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                        }
                    } else if (position == PrivacyControlActivity.this.nobodyRow) {
                        if (PrivacyControlActivity.this.rulesType == 3) {
                            radioCell.setText(LocaleController.getString("P2PNobody", R.string.P2PNobody), PrivacyControlActivity.this.lastCheckedType == 1, false);
                        } else {
                            radioCell.setText(LocaleController.getString("LastSeenNobody", R.string.LastSeenNobody), PrivacyControlActivity.this.lastCheckedType == 1, false);
                        }
                        checkedType = 1;
                        radioCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                    }
                    if (PrivacyControlActivity.this.lastCheckedType == checkedType) {
                        radioCell.setChecked(false, PrivacyControlActivity.this.enableAnimation);
                        return;
                    } else {
                        if (PrivacyControlActivity.this.currentType == checkedType) {
                            radioCell.setChecked(true, PrivacyControlActivity.this.enableAnimation);
                            return;
                        }
                        return;
                    }
                }
                int checkedType2 = 0;
                if (position == PrivacyControlActivity.this.phoneContactsRow) {
                    radioCell.setText(LocaleController.getString("LastSeenContacts", R.string.LastSeenContacts), PrivacyControlActivity.this.lastCheckedSubType == 1, false);
                    checkedType2 = 1;
                    radioCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                } else if (position == PrivacyControlActivity.this.phoneEverybodyRow) {
                    radioCell.setText(LocaleController.getString("LastSeenEverybody", R.string.LastSeenEverybody), PrivacyControlActivity.this.lastCheckedSubType == 0, true);
                    checkedType2 = 0;
                }
                if (PrivacyControlActivity.this.lastCheckedSubType == checkedType2) {
                    radioCell.setChecked(false, PrivacyControlActivity.this.enableAnimation);
                } else if (PrivacyControlActivity.this.currentSubType == checkedType2) {
                    radioCell.setChecked(true, PrivacyControlActivity.this.enableAnimation);
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == PrivacyControlActivity.this.alwaysShareRow || position == PrivacyControlActivity.this.neverShareRow || position == PrivacyControlActivity.this.p2pRow) {
                return 0;
            }
            if (position != PrivacyControlActivity.this.shareDetailRow && position != PrivacyControlActivity.this.detailRow && position != PrivacyControlActivity.this.p2pDetailRow) {
                if (position != PrivacyControlActivity.this.sectionRow && position != PrivacyControlActivity.this.shareSectionRow && position != PrivacyControlActivity.this.p2pSectionRow && position != PrivacyControlActivity.this.phoneSectionRow) {
                    if (position != PrivacyControlActivity.this.everybodyRow && position != PrivacyControlActivity.this.myContactsRow && position != PrivacyControlActivity.this.nobodyRow && position != PrivacyControlActivity.this.phoneEverybodyRow && position != PrivacyControlActivity.this.phoneContactsRow) {
                        if (position == PrivacyControlActivity.this.messageRow) {
                            return 4;
                        }
                        return position == PrivacyControlActivity.this.phoneDetailRow ? 5 : 0;
                    }
                    return 3;
                }
                return 2;
            }
            return 1;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{TextSettingsCell.class, HeaderCell.class, RadioCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader), new ThemeDescription(this.listView, 0, new Class[]{RadioCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKBOX, new Class[]{RadioCell.class}, new String[]{"radioButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_radioBackground), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKBOXCHECK, new Class[]{RadioCell.class}, new String[]{"radioButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_radioBackgroundChecked), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgInDrawable, Theme.chat_msgInMediaDrawable}, null, Theme.key_chat_inBubble), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgInSelectedDrawable, Theme.chat_msgInMediaSelectedDrawable}, null, Theme.key_chat_inBubbleSelected), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgInShadowDrawable, Theme.chat_msgInMediaShadowDrawable}, null, Theme.key_chat_inBubbleShadow), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgOutDrawable, Theme.chat_msgOutMediaDrawable}, null, Theme.key_chat_outBubble), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgOutSelectedDrawable, Theme.chat_msgOutMediaSelectedDrawable}, null, Theme.key_chat_outBubbleSelected), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgOutShadowDrawable, Theme.chat_msgOutMediaShadowDrawable}, null, Theme.key_chat_outBubbleShadow), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_messageTextIn), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_messageTextOut), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgOutCheckDrawable}, null, Theme.key_chat_outSentCheck), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgOutCheckSelectedDrawable}, null, Theme.key_chat_outSentCheckSelected), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgOutCheckReadDrawable, Theme.chat_msgOutHalfCheckDrawable}, null, Theme.key_chat_outSentCheckRead), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgOutCheckReadSelectedDrawable, Theme.chat_msgOutHalfCheckSelectedDrawable}, null, Theme.key_chat_outSentCheckReadSelected), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgMediaCheckDrawable, Theme.chat_msgMediaHalfCheckDrawable}, null, Theme.key_chat_mediaSentCheck), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_inReplyLine), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_outReplyLine), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_inReplyNameText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_outReplyNameText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_inReplyMessageText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_outReplyMessageText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_inReplyMediaMessageSelectedText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_outReplyMediaMessageSelectedText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_inTimeText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_outTimeText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_inTimeSelectedText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_outTimeSelectedText)};
    }
}
