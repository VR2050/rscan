package im.uwrkaxlmjj.ui.utils;

import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.FrameLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationsController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.phoneformat.PhoneFormat;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.MediaActivity;
import im.uwrkaxlmjj.ui.ProfileActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.SimpleTextView;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.PlayingGameDrawable;
import im.uwrkaxlmjj.ui.components.RecordStatusDrawable;
import im.uwrkaxlmjj.ui.components.RoundStatusDrawable;
import im.uwrkaxlmjj.ui.components.ScamDrawable;
import im.uwrkaxlmjj.ui.components.SendingFileDrawable;
import im.uwrkaxlmjj.ui.components.StatusDrawable;
import im.uwrkaxlmjj.ui.components.TypingDotsDrawable;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.DialogCommonList;
import im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity;
import im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class ChatActionBarHelper {
    private ActionBar actionBar;
    private ChatActivity chatActivity;
    private int currentConnectionState;
    private boolean inPreviewMode;
    private final Boolean isSysNotifyMessage;
    private CharSequence lastSubtitle;
    private String lastSubtitleColorKey;
    private int onlineCount;
    private MryTextView tvUnreadCount;
    private FrameLayout unreadCountContainer;
    private boolean[] isOnline = new boolean[1];
    private StatusDrawable[] statusDrawables = new StatusDrawable[5];

    public ChatActionBarHelper(final ChatActivity chatActivity, ActionBar actionBar, final boolean isEncryptedChat, boolean inPreviewMode) {
        this.chatActivity = chatActivity;
        this.actionBar = actionBar;
        this.inPreviewMode = inPreviewMode;
        this.isSysNotifyMessage = chatActivity.isSysNotifyMessage();
        if (chatActivity != null && actionBar != null) {
            actionBar.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$ChatActionBarHelper$y1owvLssx-qoZk6MLHsYBa039K0
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$0$ChatActionBarHelper(chatActivity, isEncryptedChat, view);
                }
            });
        }
        TLRPC.Chat chat = chatActivity.getCurrentChat();
        this.statusDrawables[0] = new TypingDotsDrawable();
        this.statusDrawables[1] = new RecordStatusDrawable();
        this.statusDrawables[2] = new SendingFileDrawable();
        this.statusDrawables[3] = new PlayingGameDrawable();
        this.statusDrawables[4] = new RoundStatusDrawable();
        int a = 0;
        while (true) {
            StatusDrawable[] statusDrawableArr = this.statusDrawables;
            if (a < statusDrawableArr.length) {
                statusDrawableArr[a].setIsChat(chat != null);
                a++;
            } else {
                return;
            }
        }
    }

    public /* synthetic */ void lambda$new$0$ChatActionBarHelper(ChatActivity chatActivity, boolean isEncryptedChat, View v) {
        TLRPC.User user = chatActivity.getCurrentUser();
        TLRPC.Chat chat = chatActivity.getCurrentChat();
        if (user != null) {
            Bundle args = new Bundle();
            if (UserObject.isUserSelf(user)) {
                args.putLong("dialog_id", chatActivity.getDialogId());
                MediaActivity fragment = new MediaActivity(args, new int[]{-1, -1, -1, -1, -1});
                fragment.setChatInfo(chatActivity.getCurrentChatInfo());
                chatActivity.presentFragment(fragment);
                return;
            }
            args.putInt("user_id", user.id);
            args.putBoolean("reportSpam", chatActivity.hasReportSpam());
            if (isEncryptedChat) {
                args.putLong("dialog_id", chatActivity.getDialogId());
            }
            if (!this.isSysNotifyMessage.booleanValue()) {
                chatActivity.presentFragment(new NewProfileActivity(args));
                return;
            }
            return;
        }
        if (chat != null) {
            Bundle args2 = new Bundle();
            args2.putInt("chat_id", chat.id);
            ProfileActivity fragment2 = new ProfileActivity(args2);
            fragment2.setChatInfo(chatActivity.getCurrentChatInfo());
            fragment2.setPlayProfileAnimation(true);
            chatActivity.presentFragment(fragment2);
        }
    }

    public void update() {
        updateTitle();
        updateOnlineCount();
        updateSubtitle();
        updateUnreadMessageCount();
        ChatActivity chatActivity = this.chatActivity;
        if (chatActivity != null) {
            updateCurrentConnectionState(ConnectionsManager.getInstance(chatActivity.getCurrentAccount()).getConnectionState());
        }
    }

    public void updateTitle() {
        ChatActivity chatActivity = this.chatActivity;
        if (chatActivity == null || this.actionBar == null) {
            return;
        }
        TLRPC.User currentUser = chatActivity.getCurrentUser();
        TLRPC.Chat currentChat = this.chatActivity.getCurrentChat();
        ContactsController contactsController = ContactsController.getInstance(this.chatActivity.getCurrentAccount());
        if (this.chatActivity.isInScheduleMode()) {
            if (UserObject.isUserSelf(currentUser)) {
                this.actionBar.setTitle(LocaleController.getString("Reminders", R.string.Reminders));
            } else {
                this.actionBar.setTitle(LocaleController.getString("ScheduledMessages", R.string.ScheduledMessages));
            }
        } else if (currentChat != null) {
            this.actionBar.setTitle(currentChat.title);
        } else if (currentUser != null) {
            if (currentUser.self) {
                this.actionBar.setTitle(LocaleController.getString("SavedMessages", R.string.SavedMessages));
            } else if (!MessagesController.isSupportUser(currentUser) && contactsController.contactsDict.get(Integer.valueOf(currentUser.id)) == null && ((contactsController.contactsDict.size() != 0 || !contactsController.isLoadingContacts()) && !TextUtils.isEmpty(currentUser.phone))) {
                this.actionBar.setTitle(PhoneFormat.getInstance().format(Marker.ANY_NON_NULL_MARKER + currentUser.phone));
            } else {
                this.actionBar.setTitle(UserObject.getName(currentUser));
            }
        }
        this.chatActivity.getParentActivity().setTitle(this.actionBar.getTitle());
    }

    public void updateSubtitle() {
        CharSequence newSubtitle;
        ChatActivity chatActivity = this.chatActivity;
        if (chatActivity == null || this.actionBar == null) {
            return;
        }
        TLRPC.User user = chatActivity.getCurrentUser();
        if (UserObject.isUserSelf(user) || this.chatActivity.isInScheduleMode()) {
            this.actionBar.setSubtitle(null);
            return;
        }
        TLRPC.Chat chat = this.chatActivity.getCurrentChat();
        CharSequence printString = MessagesController.getInstance(this.chatActivity.getCurrentAccount()).printingStrings.get(this.chatActivity.getDialogId());
        if (printString != null) {
            printString = TextUtils.replace(printString, new String[]{"..."}, new String[]{""});
        }
        boolean useOnlineColor = false;
        if (printString == null || printString.length() == 0 || (ChatObject.isChannel(chat) && !chat.megagroup)) {
            setTypingAnimation(false);
            if (chat != null) {
                TLRPC.ChatFull info = this.chatActivity.getCurrentChatInfo();
                if (ChatObject.isChannel(chat)) {
                    if (info != null && info.participants_count != 0) {
                        if (chat.megagroup) {
                            if (this.onlineCount > 1) {
                                newSubtitle = String.format("%s, %s", LocaleController.formatPluralString("Members", info.participants_count), LocaleController.formatPluralString("OnlineCount", Math.min(this.onlineCount, info.participants_count)));
                            } else {
                                newSubtitle = LocaleController.formatPluralString("Members", info.participants_count);
                            }
                        } else {
                            int[] result = new int[1];
                            String shortNumber = LocaleController.formatShortNumber(info.participants_count, result);
                            if (chat.megagroup) {
                                newSubtitle = LocaleController.formatPluralString("Members", result[0]).replace(String.format("%d", Integer.valueOf(result[0])), shortNumber);
                            } else {
                                newSubtitle = LocaleController.formatPluralString("Subscribers", result[0]).replace(String.format("%d", Integer.valueOf(result[0])), shortNumber);
                            }
                        }
                    } else if (chat.megagroup) {
                        if (info == null) {
                            newSubtitle = LocaleController.getString("Loading", R.string.Loading).toLowerCase();
                        } else if (chat.has_geo) {
                            newSubtitle = LocaleController.getString("MegaLocation", R.string.MegaLocation).toLowerCase();
                        } else {
                            CharSequence newSubtitle2 = chat.username;
                            if (!TextUtils.isEmpty(newSubtitle2)) {
                                newSubtitle = LocaleController.getString("MegaPublic", R.string.MegaPublic).toLowerCase();
                            } else {
                                newSubtitle = LocaleController.getString("MegaPrivate", R.string.MegaPrivate).toLowerCase();
                            }
                        }
                    } else if ((chat.flags & 64) != 0) {
                        newSubtitle = LocaleController.getString("ChannelPublic", R.string.ChannelPublic).toLowerCase();
                    } else {
                        newSubtitle = LocaleController.getString("ChannelPrivate", R.string.ChannelPrivate).toLowerCase();
                    }
                } else if (ChatObject.isKickedFromChat(chat)) {
                    newSubtitle = LocaleController.getString("YouWereKicked", R.string.YouWereKicked);
                } else if (ChatObject.isLeftFromChat(chat)) {
                    newSubtitle = LocaleController.getString("YouLeft", R.string.YouLeft);
                } else {
                    int count = chat.participants_count;
                    if (info != null && info.participants != null) {
                        count = info.participants.participants.size();
                    }
                    if (this.onlineCount > 1 && count != 0) {
                        newSubtitle = String.format("%s, %s", LocaleController.formatPluralString("Members", count), LocaleController.formatPluralString("OnlineCount", this.onlineCount));
                    } else {
                        newSubtitle = LocaleController.formatPluralString("Members", count);
                    }
                }
            } else if (user != null) {
                TLRPC.User newUser = MessagesController.getInstance(this.chatActivity.getCurrentAccount()).getUser(Integer.valueOf(user.id));
                if (newUser != null) {
                    user = newUser;
                }
                if (user.id == UserConfig.getInstance(this.chatActivity.getCurrentAccount()).getClientUserId()) {
                    newSubtitle = LocaleController.getString("ChatYourSelf", R.string.ChatYourSelf);
                } else if (user.id == 333000 || user.id == 777000 || user.id == 42777) {
                    newSubtitle = LocaleController.getString("ServiceNotifications", R.string.ServiceNotifications);
                } else if (MessagesController.isSupportUser(user)) {
                    newSubtitle = LocaleController.getString("SupportStatus", R.string.SupportStatus);
                } else if (!user.bot) {
                    this.isOnline[0] = false;
                    String newStatus = LocaleController.formatUserStatus(this.chatActivity.getCurrentAccount(), user, this.isOnline);
                    useOnlineColor = this.isOnline[0];
                    newSubtitle = newStatus;
                } else {
                    newSubtitle = LocaleController.getString("Bot", R.string.Bot);
                }
            } else {
                newSubtitle = "";
            }
        } else {
            newSubtitle = printString;
            useOnlineColor = true;
            setTypingAnimation(true);
        }
        this.lastSubtitleColorKey = useOnlineColor ? Theme.key_chat_status : Theme.key_actionBarDefaultSubtitle;
        if (this.isSysNotifyMessage.booleanValue()) {
            this.actionBar.setSubtitle(null);
        } else {
            if (this.lastSubtitle == null) {
                this.actionBar.setSubtitle(newSubtitle, true);
                this.actionBar.setSubtitleColor(Theme.getColor(this.lastSubtitleColorKey));
                this.actionBar.getSubtitleTextView().setTag(this.lastSubtitleColorKey);
                return;
            }
            this.lastSubtitle = newSubtitle;
        }
    }

    private void setTypingAnimation(boolean start) {
        ActionBar actionBar;
        if (this.chatActivity == null || (actionBar = this.actionBar) == null) {
            return;
        }
        SimpleTextView subtitleTextView = actionBar.getSubtitleTextView();
        if (start) {
            try {
                Integer type = MessagesController.getInstance(this.chatActivity.getCurrentAccount()).printingStringsTypes.get(this.chatActivity.getDialogId());
                if (subtitleTextView != null) {
                    subtitleTextView.setLeftDrawable(this.statusDrawables[type.intValue()]);
                }
                for (int a = 0; a < this.statusDrawables.length; a++) {
                    if (a == type.intValue()) {
                        this.statusDrawables[a].start();
                    } else {
                        this.statusDrawables[a].stop();
                    }
                }
                return;
            } catch (Exception e) {
                FileLog.e(e);
                return;
            }
        }
        if (subtitleTextView != null) {
            subtitleTextView.setLeftDrawable((Drawable) null);
        }
        int a2 = 0;
        while (true) {
            StatusDrawable[] statusDrawableArr = this.statusDrawables;
            if (a2 < statusDrawableArr.length) {
                statusDrawableArr[a2].stop();
                a2++;
            } else {
                return;
            }
        }
    }

    public void setTitleIcons(Drawable leftIcon, Drawable rightIcon) {
        ActionBar actionBar = this.actionBar;
        if (actionBar == null) {
            return;
        }
        SimpleTextView titleTextView = actionBar.getTitleTextView();
        titleTextView.setLeftDrawable(leftIcon);
        if (!(titleTextView.getRightDrawable() instanceof ScamDrawable)) {
            titleTextView.setRightDrawable(rightIcon);
        }
    }

    public void updateOnlineCount() {
        ChatActivity chatActivity = this.chatActivity;
        if (chatActivity == null || this.actionBar == null) {
            return;
        }
        this.onlineCount = 0;
        TLRPC.ChatFull info = chatActivity.getCurrentChatInfo();
        if (info == null) {
            return;
        }
        int currentTime = ConnectionsManager.getInstance(this.chatActivity.getCurrentAccount()).getCurrentTime();
        if ((info instanceof TLRPC.TL_chatFull) || ((info instanceof TLRPC.TL_channelFull) && info.participants_count <= 200 && info.participants != null)) {
            for (int a = 0; a < info.participants.participants.size(); a++) {
                TLRPC.ChatParticipant participant = info.participants.participants.get(a);
                TLRPC.User user = MessagesController.getInstance(this.chatActivity.getCurrentAccount()).getUser(Integer.valueOf(participant.user_id));
                if (user != null && user.status != null && ((user.status.expires > currentTime || user.id == UserConfig.getInstance(this.chatActivity.getCurrentAccount()).getClientUserId()) && user.status.expires > 10000)) {
                    this.onlineCount++;
                }
            }
            return;
        }
        if ((info instanceof TLRPC.TL_channelFull) && info.participants_count > 200) {
            this.onlineCount = info.online_count;
        }
    }

    public void updateCurrentConnectionState(int state) {
        if (this.actionBar == null || this.currentConnectionState == state) {
            return;
        }
        this.currentConnectionState = state;
        String title = null;
        if (state == 2) {
            title = LocaleController.getString("WaitingForNetwork", R.string.WaitingForNetwork);
        } else if (state == 1) {
            title = LocaleController.getString("Connecting", R.string.Connecting);
        } else if (state == 5) {
            title = LocaleController.getString("Updating", R.string.Updating);
        } else if (state == 4) {
            title = LocaleController.getString("ConnectingToProxy", R.string.ConnectingToProxy);
        }
        if (title == null) {
            CharSequence charSequence = this.lastSubtitle;
            if (charSequence != null) {
                this.actionBar.setSubtitle(charSequence, true);
                this.lastSubtitle = null;
                String str = this.lastSubtitleColorKey;
                if (str != null) {
                    this.actionBar.setSubtitleColor(Theme.getColor(str));
                    this.actionBar.getSubtitleTextView().setTag(this.lastSubtitleColorKey);
                    return;
                }
                return;
            }
            return;
        }
        if (this.lastSubtitle == null && this.actionBar.getSubtitleTextView() != null) {
            this.lastSubtitle = this.actionBar.getSubtitleTextView().getText();
        }
        if (this.isSysNotifyMessage.booleanValue()) {
            this.actionBar.setSubtitle(null);
            return;
        }
        this.actionBar.setSubtitle(title, true);
        this.actionBar.setSubtitleColor(Theme.getColor(Theme.key_actionBarDefaultSubtitle));
        this.actionBar.getSubtitleTextView().setTag(Theme.key_actionBarDefaultSubtitle);
    }

    public void updateUnreadMessageCount() {
        if (this.chatActivity == null || this.actionBar == null) {
            return;
        }
        int unreadCount = getAllUnreadCount();
        MryTextView mryTextView = this.tvUnreadCount;
        if (mryTextView == null) {
            if (unreadCount > 0) {
                this.unreadCountContainer = new FrameLayout(this.chatActivity.getParentActivity());
                if (Build.VERSION.SDK_INT >= 21) {
                    this.unreadCountContainer.setPadding(0, this.inPreviewMode ? 0 : AndroidUtilities.statusBarHeight, 0, 0);
                }
                this.unreadCountContainer.setVisibility(this.inPreviewMode ? 4 : 0);
                MryTextView mryTextView2 = new MryTextView(this.chatActivity.getParentActivity());
                this.tvUnreadCount = mryTextView2;
                mryTextView2.setText(String.valueOf(unreadCount));
                this.tvUnreadCount.setPadding(AndroidUtilities.dp(5.0f), 0, AndroidUtilities.dp(5.0f), 0);
                this.tvUnreadCount.setGravity(17);
                this.tvUnreadCount.setTextColor(-1);
                this.tvUnreadCount.setTextSize(12.0f);
                this.tvUnreadCount.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(10.0f), this.chatActivity.getParentActivity().getResources().getColor(R.color.color_item_menu_red_f74c31)));
                this.unreadCountContainer.addView(this.tvUnreadCount, LayoutHelper.createFrame(-2, -2, 19));
                this.actionBar.addView(this.unreadCountContainer, LayoutHelper.createFrame(-2.0f, -1.0f, 3, 35.0f, 0.0f, 0.0f, 0.0f));
                return;
            }
            return;
        }
        if (unreadCount > 0) {
            mryTextView.setText(String.valueOf(unreadCount));
            this.tvUnreadCount.setVisibility(0);
        } else {
            mryTextView.setVisibility(4);
        }
    }

    private int getAllUnreadCount() {
        ChatActivity chatActivity = this.chatActivity;
        if (chatActivity == null) {
            return 0;
        }
        int count = 0;
        MessagesController messagesController = MessagesController.getInstance(chatActivity.getCurrentAccount());
        NotificationsController notificationsController = NotificationsController.getInstance(this.chatActivity.getCurrentAccount());
        ConnectionsManager connectionsManager = ConnectionsManager.getInstance(this.chatActivity.getCurrentAccount());
        for (TLRPC.Dialog dialog : messagesController.getAllDialogs()) {
            if (notificationsController.showBadgeNumber) {
                if (notificationsController.showBadgeMessages) {
                    if (notificationsController.showBadgeMuted || dialog.notify_settings == null || (!dialog.notify_settings.silent && dialog.notify_settings.mute_until <= connectionsManager.getCurrentTime())) {
                        count += dialog.unread_count;
                    }
                } else if (notificationsController.showBadgeMuted || dialog.notify_settings == null || (!dialog.notify_settings.silent && dialog.notify_settings.mute_until <= connectionsManager.getCurrentTime())) {
                    if (dialog.unread_count != 0) {
                        count++;
                    }
                }
            }
        }
        return count;
    }

    public void setInPreviewMode(boolean inPreviewMode) {
        this.inPreviewMode = inPreviewMode;
        if (this.unreadCountContainer != null) {
            if (Build.VERSION.SDK_INT >= 21) {
                this.unreadCountContainer.setPadding(0, inPreviewMode ? 0 : AndroidUtilities.statusBarHeight, 0, 0);
            }
            this.unreadCountContainer.setVisibility(inPreviewMode ? 8 : 0);
        }
    }

    public void startCall(final TLRPC.User user) {
        List<String> list = new ArrayList<>();
        list.add(LocaleController.getString("menu_voice_chat", R.string.menu_voice_chat));
        list.add(LocaleController.getString("menu_video_chat", R.string.menu_video_chat));
        List<Integer> list1 = new ArrayList<>();
        list1.add(Integer.valueOf(R.drawable.menu_voice_call));
        list1.add(Integer.valueOf(R.drawable.menu_video_call));
        DialogCommonList dialogCommonList = new DialogCommonList(this.chatActivity.getParentActivity(), list, list1, Color.parseColor("#222222"), new DialogCommonList.RecyclerviewItemClickCallBack() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$ChatActionBarHelper$NTWv_k-U8OFLQhvVZxVgMlEvY98
            @Override // im.uwrkaxlmjj.ui.dialogs.DialogCommonList.RecyclerviewItemClickCallBack
            public final void onRecyclerviewItemClick(int i) {
                this.f$0.lambda$startCall$1$ChatActionBarHelper(user, i);
            }
        }, 1);
        dialogCommonList.show();
    }

    public /* synthetic */ void lambda$startCall$1$ChatActionBarHelper(TLRPC.User user, int position) {
        if (position == 0) {
            if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                if (user.mutual_contact) {
                    int currentConnectionState = ConnectionsManager.getInstance(this.chatActivity.getCurrentAccount()).getConnectionState();
                    if (currentConnectionState == 2 || currentConnectionState == 1) {
                        ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_network", R.string.visual_call_no_network));
                        return;
                    }
                    Intent intent = new Intent();
                    intent.setClass(this.chatActivity.getParentActivity(), VisualCallActivity.class);
                    intent.putExtra("CallType", 1);
                    ArrayList<Integer> ArrInputPeers = new ArrayList<>();
                    ArrInputPeers.add(Integer.valueOf(user.id));
                    intent.putExtra("ArrayUser", ArrInputPeers);
                    intent.putExtra("channel", new ArrayList());
                    this.chatActivity.getParentActivity().startActivity(intent);
                    return;
                }
                ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_friend_tip", R.string.visual_call_no_friend_tip));
                return;
            }
            ToastUtils.show((CharSequence) LocaleController.getString("visual_call_busing_tip", R.string.visual_call_busing_tip));
            return;
        }
        if (position == 1) {
            if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                if (user.mutual_contact) {
                    int currentConnectionState2 = ConnectionsManager.getInstance(this.chatActivity.getCurrentAccount()).getConnectionState();
                    if (currentConnectionState2 == 2 || currentConnectionState2 == 1) {
                        ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_network", R.string.visual_call_no_network));
                        return;
                    }
                    Intent intent2 = new Intent();
                    intent2.setClass(this.chatActivity.getParentActivity(), VisualCallActivity.class);
                    intent2.putExtra("CallType", 2);
                    ArrayList<Integer> ArrInputPeers2 = new ArrayList<>();
                    ArrInputPeers2.add(Integer.valueOf(user.id));
                    intent2.putExtra("ArrayUser", ArrInputPeers2);
                    intent2.putExtra("channel", new ArrayList());
                    this.chatActivity.getParentActivity().startActivity(intent2);
                    return;
                }
                ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_friend_tip", R.string.visual_call_no_friend_tip));
                return;
            }
            ToastUtils.show((CharSequence) LocaleController.getString("visual_call_busing_tip", R.string.visual_call_busing_tip));
        }
    }
}
