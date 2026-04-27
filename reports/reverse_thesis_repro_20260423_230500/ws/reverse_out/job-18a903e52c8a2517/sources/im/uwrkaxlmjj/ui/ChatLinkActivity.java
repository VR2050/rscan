package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.DispatchQueue;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.GroupCreateFinalActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.ManageChatTextCell;
import im.uwrkaxlmjj.ui.cells.ManageChatUserCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChatLinkActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private static final int search_button = 0;
    private int chatEndRow;
    private int chatStartRow;
    private ArrayList<TLRPC.Chat> chats = new ArrayList<>();
    private int createChatRow;
    private TLRPC.Chat currentChat;
    private int currentChatId;
    private int detailRow;
    private EmptyTextProgressView emptyView;
    private int helpRow;
    private TLRPC.ChatFull info;
    private boolean isChannel;
    private RecyclerListView listView;
    private ListAdapter listViewAdapter;
    private boolean loadingChats;
    private int removeChatRow;
    private int rowCount;
    private SearchAdapter searchAdapter;
    private ActionBarMenuItem searchItem;
    private boolean searchWas;
    private boolean searching;
    private boolean waitingForChatCreate;
    private TLRPC.Chat waitingForFullChat;
    private AlertDialog waitingForFullChatProgressAlert;

    public ChatLinkActivity(int chatId) {
        this.currentChatId = chatId;
        TLRPC.Chat chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(chatId));
        this.currentChat = chat;
        this.isChannel = ChatObject.isChannel(chat) && !this.currentChat.megagroup;
    }

    private void updateRows() {
        TLRPC.Chat chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.currentChatId));
        this.currentChat = chat;
        if (chat == null) {
            return;
        }
        this.rowCount = 0;
        this.helpRow = -1;
        this.createChatRow = -1;
        this.chatStartRow = -1;
        this.chatEndRow = -1;
        this.removeChatRow = -1;
        this.detailRow = -1;
        int i = 0 + 1;
        this.rowCount = i;
        this.helpRow = 0;
        if (this.isChannel) {
            if (this.info.linked_chat_id == 0) {
                int i2 = this.rowCount;
                this.rowCount = i2 + 1;
                this.createChatRow = i2;
            }
            int i3 = this.rowCount;
            this.chatStartRow = i3;
            int size = i3 + this.chats.size();
            this.rowCount = size;
            this.chatEndRow = size;
            if (this.info.linked_chat_id != 0) {
                int i4 = this.rowCount;
                this.rowCount = i4 + 1;
                this.createChatRow = i4;
            }
            int i5 = this.rowCount;
            this.rowCount = i5 + 1;
            this.detailRow = i5;
        } else {
            this.chatStartRow = i;
            int size2 = i + this.chats.size();
            this.rowCount = size2;
            this.chatEndRow = size2;
            int i6 = size2 + 1;
            this.rowCount = i6;
            this.createChatRow = size2;
            this.rowCount = i6 + 1;
            this.detailRow = i6;
        }
        ListAdapter listAdapter = this.listViewAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
        ActionBarMenuItem actionBarMenuItem = this.searchItem;
        if (actionBarMenuItem != null) {
            actionBarMenuItem.setVisibility(this.chats.size() <= 10 ? 8 : 0);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        getNotificationCenter().addObserver(this, NotificationCenter.chatInfoDidLoad);
        loadChats();
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        getNotificationCenter().removeObserver(this, NotificationCenter.chatInfoDidLoad);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.chatInfoDidLoad) {
            TLRPC.ChatFull chatFull = (TLRPC.ChatFull) args[0];
            if (chatFull.id == this.currentChatId) {
                this.info = chatFull;
                loadChats();
                updateRows();
                return;
            }
            TLRPC.Chat chat = this.waitingForFullChat;
            if (chat != null && chat.id == chatFull.id) {
                try {
                    this.waitingForFullChatProgressAlert.dismiss();
                } catch (Throwable th) {
                }
                this.waitingForFullChatProgressAlert = null;
                showLinkAlert(this.waitingForFullChat, false);
                this.waitingForFullChat = null;
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.searching = false;
        this.searchWas = false;
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString("Discussion", R.string.Discussion));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.ChatLinkActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    ChatLinkActivity.this.finishFragment();
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        ActionBarMenuItem actionBarMenuItemSearchListener = menu.addItem(0, R.drawable.ic_ab_search).setIsSearchField(true).setActionBarMenuItemSearchListener(new ActionBarMenuItem.ActionBarMenuItemSearchListener() { // from class: im.uwrkaxlmjj.ui.ChatLinkActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onSearchExpand() {
                ChatLinkActivity.this.searching = true;
                ChatLinkActivity.this.emptyView.setShowAtCenter(true);
            }

            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onSearchCollapse() {
                ChatLinkActivity.this.searchAdapter.searchDialogs(null);
                ChatLinkActivity.this.searching = false;
                ChatLinkActivity.this.searchWas = false;
                ChatLinkActivity.this.listView.setAdapter(ChatLinkActivity.this.listViewAdapter);
                ChatLinkActivity.this.listViewAdapter.notifyDataSetChanged();
                ChatLinkActivity.this.listView.setFastScrollVisible(true);
                ChatLinkActivity.this.listView.setVerticalScrollBarEnabled(false);
                ChatLinkActivity.this.emptyView.setShowAtCenter(false);
                ChatLinkActivity.this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
                ChatLinkActivity.this.fragmentView.setTag(Theme.key_windowBackgroundGray);
                ChatLinkActivity.this.emptyView.showProgress();
            }

            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onTextChanged(EditText editText) {
                if (ChatLinkActivity.this.searchAdapter == null) {
                    return;
                }
                String text = editText.getText().toString();
                if (text.length() != 0) {
                    ChatLinkActivity.this.searchWas = true;
                    if (ChatLinkActivity.this.listView != null && ChatLinkActivity.this.listView.getAdapter() != ChatLinkActivity.this.searchAdapter) {
                        ChatLinkActivity.this.listView.setAdapter(ChatLinkActivity.this.searchAdapter);
                        ChatLinkActivity.this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                        ChatLinkActivity.this.fragmentView.setTag(Theme.key_windowBackgroundWhite);
                        ChatLinkActivity.this.searchAdapter.notifyDataSetChanged();
                        ChatLinkActivity.this.listView.setFastScrollVisible(false);
                        ChatLinkActivity.this.listView.setVerticalScrollBarEnabled(true);
                        ChatLinkActivity.this.emptyView.showProgress();
                    }
                }
                ChatLinkActivity.this.searchAdapter.searchDialogs(text);
            }
        });
        this.searchItem = actionBarMenuItemSearchListener;
        actionBarMenuItemSearchListener.setSearchFieldHint(LocaleController.getString("Search", R.string.Search));
        this.searchAdapter = new SearchAdapter(context);
        this.fragmentView = new FrameLayout(context);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.fragmentView.setTag(Theme.key_windowBackgroundGray);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.emptyView = emptyTextProgressView;
        emptyTextProgressView.showProgress();
        this.emptyView.setText(LocaleController.getString("NoResult", R.string.NoResult));
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
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -2, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f)));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$hNWJuCx8mwSNfdWRarcEesDPknI
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$createView$5$ChatLinkActivity(view, i);
            }
        });
        updateRows();
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$5$ChatLinkActivity(View view, int position) {
        TLRPC.Chat chat;
        String title;
        String message;
        if (getParentActivity() == null) {
            return;
        }
        RecyclerView.Adapter adapter = this.listView.getAdapter();
        SearchAdapter searchAdapter = this.searchAdapter;
        if (adapter == searchAdapter) {
            chat = searchAdapter.getItem(position);
        } else {
            int i = this.chatStartRow;
            if (position >= i && position < this.chatEndRow) {
                chat = this.chats.get(position - i);
            } else {
                chat = null;
            }
        }
        if (chat != null) {
            if (this.isChannel && this.info.linked_chat_id == 0) {
                showLinkAlert(chat, true);
                return;
            }
            Bundle args = new Bundle();
            args.putInt("chat_id", chat.id);
            presentFragment(new ChatActivity(args));
            return;
        }
        if (position == this.createChatRow) {
            if (this.isChannel && this.info.linked_chat_id == 0) {
                Bundle args2 = new Bundle();
                ArrayList<Integer> result = new ArrayList<>();
                result.add(Integer.valueOf(getUserConfig().getClientUserId()));
                args2.putIntegerArrayList("result", result);
                args2.putInt("chatType", 4);
                GroupCreateFinalActivity activity = new GroupCreateFinalActivity(args2);
                activity.setDelegate(new GroupCreateFinalActivity.GroupCreateFinalActivityDelegate() { // from class: im.uwrkaxlmjj.ui.ChatLinkActivity.3
                    @Override // im.uwrkaxlmjj.ui.GroupCreateFinalActivity.GroupCreateFinalActivityDelegate
                    public void didStartChatCreation() {
                    }

                    @Override // im.uwrkaxlmjj.ui.GroupCreateFinalActivity.GroupCreateFinalActivityDelegate
                    public void didFinishChatCreation(GroupCreateFinalActivity fragment, int chatId) {
                        ChatLinkActivity chatLinkActivity = ChatLinkActivity.this;
                        chatLinkActivity.linkChat(chatLinkActivity.getMessagesController().getChat(Integer.valueOf(chatId)), fragment);
                    }

                    @Override // im.uwrkaxlmjj.ui.GroupCreateFinalActivity.GroupCreateFinalActivityDelegate
                    public void didFailChatCreation() {
                    }
                });
                presentFragment(activity);
                return;
            }
            if (this.chats.isEmpty()) {
                return;
            }
            TLRPC.Chat c = this.chats.get(0);
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            if (this.isChannel) {
                title = LocaleController.getString("DiscussionUnlinkGroup", R.string.DiscussionUnlinkGroup);
                message = LocaleController.formatString("DiscussionUnlinkChannelAlert", R.string.DiscussionUnlinkChannelAlert, c.title);
            } else {
                title = LocaleController.getString("DiscussionUnlink", R.string.DiscussionUnlinkChannel);
                message = LocaleController.formatString("DiscussionUnlinkGroupAlert", R.string.DiscussionUnlinkGroupAlert, c.title);
            }
            builder.setTitle(title);
            builder.setMessage(AndroidUtilities.replaceTags(message));
            builder.setPositiveButton(LocaleController.getString("DiscussionUnlink", R.string.DiscussionUnlink), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$oQFpUjmot1awO6t6DOQtQ1Eker4
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i2) {
                    this.f$0.lambda$null$4$ChatLinkActivity(dialogInterface, i2);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            AlertDialog dialog = builder.create();
            showDialog(dialog);
            TextView button = (TextView) dialog.getButton(-1);
            if (button != null) {
                button.setTextColor(Theme.getColor(Theme.key_dialogTextRed2));
            }
        }
    }

    public /* synthetic */ void lambda$null$4$ChatLinkActivity(DialogInterface dialogInterface, int i) {
        if (!this.isChannel || this.info.linked_chat_id != 0) {
            final AlertDialog[] progressDialog = {new AlertDialog(getParentActivity(), 3)};
            TLRPC.TL_channels_setDiscussionGroup req = new TLRPC.TL_channels_setDiscussionGroup();
            if (this.isChannel) {
                req.broadcast = MessagesController.getInputChannel(this.currentChat);
                req.group = new TLRPC.TL_inputChannelEmpty();
            } else {
                req.broadcast = new TLRPC.TL_inputChannelEmpty();
                req.group = MessagesController.getInputChannel(this.currentChat);
            }
            final int requestId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$b750J27I35CdL1B_sqxSCSQaKdg
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$1$ChatLinkActivity(progressDialog, tLObject, tL_error);
                }
            });
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$DJ1TBBZYGmo3heZAfQ15fw5BJiI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$3$ChatLinkActivity(progressDialog, requestId);
                }
            }, 500L);
        }
    }

    public /* synthetic */ void lambda$null$1$ChatLinkActivity(final AlertDialog[] progressDialog, TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$vcYxv4hWnVX-veJuGICyxBVsbIk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$0$ChatLinkActivity(progressDialog);
            }
        });
    }

    public /* synthetic */ void lambda$null$0$ChatLinkActivity(AlertDialog[] progressDialog) {
        try {
            progressDialog[0].dismiss();
        } catch (Throwable th) {
        }
        progressDialog[0] = null;
        this.info.linked_chat_id = 0;
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.chatInfoDidLoad, this.info, 0, false, null);
        getMessagesController().loadFullChat(this.currentChatId, 0, true);
        if (!this.isChannel) {
            finishFragment();
        }
    }

    public /* synthetic */ void lambda$null$3$ChatLinkActivity(AlertDialog[] progressDialog, final int requestId) {
        if (progressDialog[0] == null) {
            return;
        }
        progressDialog[0].setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$65CZubKUf8Q3nvy1OQ2acski8u0
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$null$2$ChatLinkActivity(requestId, dialogInterface);
            }
        });
        showDialog(progressDialog[0]);
    }

    public /* synthetic */ void lambda$null$2$ChatLinkActivity(int requestId, DialogInterface dialog) {
        ConnectionsManager.getInstance(this.currentAccount).cancelRequest(requestId, true);
    }

    private void showLinkAlert(final TLRPC.Chat chat, boolean query) {
        String message;
        final TLRPC.ChatFull chatFull = getMessagesController().getChatFull(chat.id);
        if (chatFull == null) {
            if (query) {
                getMessagesController().loadFullChat(chat.id, 0, true);
                this.waitingForFullChat = chat;
                this.waitingForFullChatProgressAlert = new AlertDialog(getParentActivity(), 3);
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$0fUX9ProQ-_4obAZOc5Lx5Gylvc
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$showLinkAlert$7$ChatLinkActivity();
                    }
                }, 500L);
                return;
            }
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        TextView messageTextView = new TextView(getParentActivity());
        messageTextView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        messageTextView.setTextSize(1, 16.0f);
        messageTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
        if (TextUtils.isEmpty(chat.username)) {
            message = LocaleController.formatString("DiscussionLinkGroupPublicPrivateAlert", R.string.DiscussionLinkGroupPublicPrivateAlert, chat.title, this.currentChat.title);
        } else if (TextUtils.isEmpty(this.currentChat.username)) {
            message = LocaleController.formatString("DiscussionLinkGroupPrivateAlert", R.string.DiscussionLinkGroupPrivateAlert, chat.title, this.currentChat.title);
        } else {
            message = LocaleController.formatString("DiscussionLinkGroupPublicAlert", R.string.DiscussionLinkGroupPublicAlert, chat.title, this.currentChat.title);
        }
        if (chatFull.hidden_prehistory) {
            message = message + "\n\n" + LocaleController.getString("DiscussionLinkGroupAlertHistory", R.string.DiscussionLinkGroupAlertHistory);
        }
        messageTextView.setText(AndroidUtilities.replaceTags(message));
        FrameLayout frameLayout2 = new FrameLayout(getParentActivity());
        builder.setView(frameLayout2);
        AvatarDrawable avatarDrawable = new AvatarDrawable();
        avatarDrawable.setTextSize(AndroidUtilities.dp(12.0f));
        BackupImageView imageView = new BackupImageView(getParentActivity());
        imageView.setRoundRadius(AndroidUtilities.dp(20.0f));
        frameLayout2.addView(imageView, LayoutHelper.createFrame(40.0f, 40.0f, (LocaleController.isRTL ? 5 : 3) | 48, 22.0f, 5.0f, 22.0f, 0.0f));
        TextView textView = new TextView(getParentActivity());
        textView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultSubmenuItem));
        textView.setTextSize(1, 20.0f);
        textView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        textView.setLines(1);
        textView.setMaxLines(1);
        textView.setSingleLine(true);
        textView.setGravity((LocaleController.isRTL ? 5 : 3) | 16);
        textView.setEllipsize(TextUtils.TruncateAt.END);
        textView.setText(chat.title);
        frameLayout2.addView(textView, LayoutHelper.createFrame(-1.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 21 : 76, 11.0f, LocaleController.isRTL ? 76 : 21, 0.0f));
        frameLayout2.addView(messageTextView, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, 24.0f, 57.0f, 24.0f, 9.0f));
        avatarDrawable.setInfo(chat);
        imageView.setImage(ImageLocation.getForChat(chat, false), "50_50", avatarDrawable, chat);
        builder.setPositiveButton(LocaleController.getString("DiscussionLinkGroup", R.string.DiscussionLinkGroup), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$BXbJ2FgA0Dj4t55pKiYzkip7vq8
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showLinkAlert$8$ChatLinkActivity(chatFull, chat, dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$showLinkAlert$7$ChatLinkActivity() {
        AlertDialog alertDialog = this.waitingForFullChatProgressAlert;
        if (alertDialog == null) {
            return;
        }
        alertDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$QqUgAcK0Xevyv2N1i5M4TN7ztGI
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$null$6$ChatLinkActivity(dialogInterface);
            }
        });
        showDialog(this.waitingForFullChatProgressAlert);
    }

    public /* synthetic */ void lambda$null$6$ChatLinkActivity(DialogInterface dialog) {
        this.waitingForFullChat = null;
    }

    public /* synthetic */ void lambda$showLinkAlert$8$ChatLinkActivity(TLRPC.ChatFull chatFull, TLRPC.Chat chat, DialogInterface dialogInterface, int i) {
        if (chatFull.hidden_prehistory) {
            MessagesController.getInstance(this.currentAccount).toogleChannelInvitesHistory(chat.id, false);
        }
        linkChat(chat, null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void linkChat(final TLRPC.Chat chat, final BaseFragment createFragment) {
        if (chat == null) {
            return;
        }
        if (!ChatObject.isChannel(chat)) {
            MessagesController.getInstance(this.currentAccount).convertToMegaGroup(getParentActivity(), chat.id, this, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$KJxU-RWVL6HYdC91tRTtAz95GRI
                @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
                public final void run(int i) {
                    this.f$0.lambda$linkChat$9$ChatLinkActivity(createFragment, i);
                }
            });
            return;
        }
        final AlertDialog[] progressDialog = new AlertDialog[1];
        progressDialog[0] = createFragment != null ? null : new AlertDialog(getParentActivity(), 3);
        TLRPC.TL_channels_setDiscussionGroup req = new TLRPC.TL_channels_setDiscussionGroup();
        req.broadcast = MessagesController.getInputChannel(this.currentChat);
        req.group = MessagesController.getInputChannel(chat);
        final int requestId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$w3s7MQl-z735uCwQF5cSaq8jUig
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$linkChat$11$ChatLinkActivity(progressDialog, chat, createFragment, tLObject, tL_error);
            }
        });
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$JEmecA9BUhbsy1P8OypLEIdZCFI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$linkChat$13$ChatLinkActivity(progressDialog, requestId);
            }
        }, 500L);
    }

    public /* synthetic */ void lambda$linkChat$9$ChatLinkActivity(BaseFragment createFragment, int param) {
        MessagesController.getInstance(this.currentAccount).toogleChannelInvitesHistory(param, false);
        linkChat(getMessagesController().getChat(Integer.valueOf(param)), createFragment);
    }

    public /* synthetic */ void lambda$linkChat$11$ChatLinkActivity(final AlertDialog[] progressDialog, final TLRPC.Chat chat, final BaseFragment createFragment, TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$6T6yXGEYYYSfWTltFz1VsM3dzA8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$10$ChatLinkActivity(progressDialog, chat, createFragment);
            }
        });
    }

    public /* synthetic */ void lambda$null$10$ChatLinkActivity(AlertDialog[] progressDialog, TLRPC.Chat chat, BaseFragment createFragment) {
        if (progressDialog[0] != null) {
            try {
                progressDialog[0].dismiss();
            } catch (Throwable th) {
            }
            progressDialog[0] = null;
        }
        this.info.linked_chat_id = chat.id;
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.chatInfoDidLoad, this.info, 0, false, null);
        getMessagesController().loadFullChat(this.currentChatId, 0, true);
        if (createFragment != null) {
            removeSelfFromStack();
            createFragment.finishFragment();
        } else {
            finishFragment();
        }
    }

    public /* synthetic */ void lambda$linkChat$13$ChatLinkActivity(AlertDialog[] progressDialog, final int requestId) {
        if (progressDialog[0] == null) {
            return;
        }
        progressDialog[0].setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$bGfhyd4GoZlUQBBwyp0IbrCXBog
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$null$12$ChatLinkActivity(requestId, dialogInterface);
            }
        });
        showDialog(progressDialog[0]);
    }

    public /* synthetic */ void lambda$null$12$ChatLinkActivity(int requestId, DialogInterface dialog) {
        ConnectionsManager.getInstance(this.currentAccount).cancelRequest(requestId, true);
    }

    public void setInfo(TLRPC.ChatFull chatFull) {
        this.info = chatFull;
    }

    private void loadChats() {
        if (this.info.linked_chat_id != 0) {
            this.chats.clear();
            TLRPC.Chat chat = getMessagesController().getChat(Integer.valueOf(this.info.linked_chat_id));
            if (chat != null) {
                this.chats.add(chat);
            }
            ActionBarMenuItem actionBarMenuItem = this.searchItem;
            if (actionBarMenuItem != null) {
                actionBarMenuItem.setVisibility(8);
            }
        }
        if (this.loadingChats || !this.isChannel || this.info.linked_chat_id != 0) {
            return;
        }
        this.loadingChats = true;
        TLRPC.TL_channels_getGroupsForDiscussion req = new TLRPC.TL_channels_getGroupsForDiscussion();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$5v38UNmXLg2G4yKlbVxTBcWGe7w
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadChats$15$ChatLinkActivity(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadChats$15$ChatLinkActivity(final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$mLkY-URpH27FlzYFxaxqYjq_zvc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$14$ChatLinkActivity(response);
            }
        });
    }

    public /* synthetic */ void lambda$null$14$ChatLinkActivity(TLObject response) {
        if (response instanceof TLRPC.messages_Chats) {
            TLRPC.messages_Chats res = (TLRPC.messages_Chats) response;
            getMessagesController().putChats(res.chats, false);
            this.chats = res.chats;
        }
        this.loadingChats = false;
        updateRows();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listViewAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    public class HintInnerCell extends FrameLayout {
        private ImageView imageView;
        private TextView messageTextView;

        public HintInnerCell(Context context) {
            super(context);
            ImageView imageView = new ImageView(context);
            this.imageView = imageView;
            imageView.setImageResource(Theme.getCurrentTheme().isDark() ? R.drawable.tip6_dark : R.drawable.tip6);
            addView(this.imageView, LayoutHelper.createFrame(-2.0f, -2.0f, 49, 0.0f, 20.0f, 8.0f, 0.0f));
            TextView textView = new TextView(context);
            this.messageTextView = textView;
            textView.setTextColor(Theme.getColor(Theme.key_chats_message));
            this.messageTextView.setTextSize(1, 14.0f);
            this.messageTextView.setGravity(17);
            if (ChatLinkActivity.this.isChannel) {
                if (ChatLinkActivity.this.info != null && ChatLinkActivity.this.info.linked_chat_id != 0) {
                    TLRPC.Chat chat = ChatLinkActivity.this.getMessagesController().getChat(Integer.valueOf(ChatLinkActivity.this.info.linked_chat_id));
                    if (chat != null) {
                        this.messageTextView.setText(AndroidUtilities.replaceTags(LocaleController.formatString("DiscussionChannelGroupSetHelp", R.string.DiscussionChannelGroupSetHelp, chat.title)));
                    }
                } else {
                    this.messageTextView.setText(LocaleController.getString("DiscussionChannelHelp", R.string.DiscussionChannelHelp));
                }
            } else {
                TLRPC.Chat chat2 = ChatLinkActivity.this.getMessagesController().getChat(Integer.valueOf(ChatLinkActivity.this.info.linked_chat_id));
                if (chat2 != null) {
                    this.messageTextView.setText(AndroidUtilities.replaceTags(LocaleController.formatString("DiscussionGroupHelp", R.string.DiscussionGroupHelp, chat2.title)));
                }
            }
            addView(this.messageTextView, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 52.0f, 124.0f, 52.0f, 27.0f));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class SearchAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;
        private ArrayList<TLRPC.Chat> searchResult = new ArrayList<>();
        private ArrayList<CharSequence> searchResultNames = new ArrayList<>();
        private Runnable searchRunnable;
        private int searchStartRow;
        private int totalCount;

        public SearchAdapter(Context context) {
            this.mContext = context;
        }

        public void searchDialogs(final String query) {
            if (this.searchRunnable != null) {
                Utilities.searchQueue.cancelRunnable(this.searchRunnable);
                this.searchRunnable = null;
            }
            if (TextUtils.isEmpty(query)) {
                this.searchResult.clear();
                this.searchResultNames.clear();
                notifyDataSetChanged();
            } else {
                DispatchQueue dispatchQueue = Utilities.searchQueue;
                Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$SearchAdapter$WPfriAqKbiqUdag1kneTl6Uektw
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$searchDialogs$0$ChatLinkActivity$SearchAdapter(query);
                    }
                };
                this.searchRunnable = runnable;
                dispatchQueue.postRunnable(runnable, 300L);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* JADX INFO: renamed from: processSearch, reason: merged with bridge method [inline-methods] */
        public void lambda$searchDialogs$0$ChatLinkActivity$SearchAdapter(final String query) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$SearchAdapter$lguk3r0VKkDkRiLDwf5HwQkH3cQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$processSearch$2$ChatLinkActivity$SearchAdapter(query);
                }
            });
        }

        public /* synthetic */ void lambda$processSearch$2$ChatLinkActivity$SearchAdapter(final String query) {
            this.searchRunnable = null;
            final ArrayList<TLRPC.Chat> chatsCopy = new ArrayList<>(ChatLinkActivity.this.chats);
            Utilities.searchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$SearchAdapter$8ckwDopYygcPjFllNI35AqjLFvE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$1$ChatLinkActivity$SearchAdapter(query, chatsCopy);
                }
            });
        }

        /* JADX WARN: Removed duplicated region for block: B:49:0x0105 A[LOOP:1: B:25:0x0074->B:49:0x0105, LOOP_END] */
        /* JADX WARN: Removed duplicated region for block: B:57:0x00ca A[SYNTHETIC] */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public /* synthetic */ void lambda$null$1$ChatLinkActivity$SearchAdapter(java.lang.String r19, java.util.ArrayList r20) {
            /*
                Method dump skipped, instruction units count: 283
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatLinkActivity.SearchAdapter.lambda$null$1$ChatLinkActivity$SearchAdapter(java.lang.String, java.util.ArrayList):void");
        }

        private void updateSearchResults(final ArrayList<TLRPC.Chat> chats, final ArrayList<CharSequence> names) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$SearchAdapter$UbKyYT0UAnNGjTxazfjlKZ7v8WY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$updateSearchResults$3$ChatLinkActivity$SearchAdapter(chats, names);
                }
            });
        }

        public /* synthetic */ void lambda$updateSearchResults$3$ChatLinkActivity$SearchAdapter(ArrayList chats, ArrayList names) {
            this.searchResult = chats;
            this.searchResultNames = names;
            if (ChatLinkActivity.this.listView.getAdapter() == ChatLinkActivity.this.searchAdapter) {
                ChatLinkActivity.this.emptyView.showTextView();
            }
            notifyDataSetChanged();
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() != 1;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return this.searchResult.size();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            this.totalCount = 0;
            int count = this.searchResult.size();
            if (count != 0) {
                int i = this.totalCount;
                this.searchStartRow = i;
                this.totalCount = i + count + 1;
            } else {
                this.searchStartRow = -1;
            }
            super.notifyDataSetChanged();
        }

        public TLRPC.Chat getItem(int i) {
            return this.searchResult.get(i);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = new ManageChatUserCell(this.mContext, 6, 2, false);
            view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            TLRPC.Chat chat = this.searchResult.get(position);
            String un = chat.username;
            CharSequence username = null;
            CharSequence name = this.searchResultNames.get(position);
            if (name != null && !TextUtils.isEmpty(un)) {
                if (name.toString().startsWith("@" + un)) {
                    username = name;
                    name = null;
                }
            }
            ManageChatUserCell userCell = (ManageChatUserCell) holder.itemView;
            userCell.setTag(Integer.valueOf(position));
            userCell.setData(chat, name, username, false);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewRecycled(RecyclerView.ViewHolder holder) {
            if (holder.itemView instanceof ManageChatUserCell) {
                ((ManageChatUserCell) holder.itemView).recycle();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            return 0;
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int type = holder.getItemViewType();
            return type == 0 || type == 2;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (!ChatLinkActivity.this.loadingChats) {
                return ChatLinkActivity.this.rowCount;
            }
            return 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                View view2 = new ManageChatUserCell(this.mContext, 6, 2, false);
                view2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                view = view2;
            } else if (viewType == 1) {
                view = new TextInfoPrivacyCell(this.mContext);
            } else if (viewType == 2) {
                View view3 = new ManageChatTextCell(this.mContext);
                view3.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                view = view3;
            } else {
                view = ChatLinkActivity.this.new HintInnerCell(this.mContext);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            CharSequence charSequence;
            int itemViewType = holder.getItemViewType();
            boolean z = true;
            if (itemViewType == 0) {
                ManageChatUserCell userCell = (ManageChatUserCell) holder.itemView;
                userCell.setTag(Integer.valueOf(position));
                TLRPC.Chat chat = (TLRPC.Chat) ChatLinkActivity.this.chats.get(position - ChatLinkActivity.this.chatStartRow);
                if (TextUtils.isEmpty(chat.username)) {
                    charSequence = null;
                } else {
                    charSequence = "@" + chat.username;
                }
                if (position == ChatLinkActivity.this.chatEndRow - 1 && ChatLinkActivity.this.info.linked_chat_id == 0) {
                    z = false;
                }
                userCell.setData(chat, null, charSequence, z);
                return;
            }
            if (itemViewType == 1) {
                TextInfoPrivacyCell privacyCell = (TextInfoPrivacyCell) holder.itemView;
                if (position == ChatLinkActivity.this.detailRow) {
                    if (ChatLinkActivity.this.isChannel) {
                        privacyCell.setText(LocaleController.getString("DiscussionChannelHelp2", R.string.DiscussionChannelHelp2));
                        return;
                    } else {
                        privacyCell.setText(LocaleController.getString("DiscussionGroupHelp2", R.string.DiscussionGroupHelp2));
                        return;
                    }
                }
                return;
            }
            if (itemViewType == 2) {
                ManageChatTextCell actionCell = (ManageChatTextCell) holder.itemView;
                if (ChatLinkActivity.this.isChannel) {
                    if (ChatLinkActivity.this.info.linked_chat_id != 0) {
                        actionCell.setColors(Theme.key_windowBackgroundWhiteRedText5, Theme.key_windowBackgroundWhiteRedText5);
                        actionCell.setText(LocaleController.getString("DiscussionUnlinkGroup", R.string.DiscussionUnlinkGroup), null, R.drawable.actions_remove_user, false);
                        return;
                    } else {
                        actionCell.setColors(Theme.key_windowBackgroundWhiteBlueIcon, Theme.key_windowBackgroundWhiteBlueButton);
                        actionCell.setText(LocaleController.getString("DiscussionCreateGroup", R.string.DiscussionCreateGroup), null, R.drawable.menu_groups, false);
                        actionCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                        return;
                    }
                }
                actionCell.setColors(Theme.key_windowBackgroundWhiteRedText5, Theme.key_windowBackgroundWhiteRedText5);
                actionCell.setText(LocaleController.getString("DiscussionUnlinkChannel", R.string.DiscussionUnlinkChannel), null, R.drawable.actions_remove_user, false);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewRecycled(RecyclerView.ViewHolder holder) {
            if (holder.itemView instanceof ManageChatUserCell) {
                ((ManageChatUserCell) holder.itemView).recycle();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != ChatLinkActivity.this.helpRow) {
                if (position != ChatLinkActivity.this.createChatRow && position != ChatLinkActivity.this.removeChatRow) {
                    if (position >= ChatLinkActivity.this.chatStartRow && position < ChatLinkActivity.this.chatEndRow) {
                        return 0;
                    }
                    return 1;
                }
                return 2;
            }
            return 3;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatLinkActivity$Ow9H-gkiKvCJMg0tNVBEXM5ZToo
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$16$ChatLinkActivity();
            }
        };
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{ManageChatUserCell.class, ManageChatTextCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND | ThemeDescription.FLAG_CHECKTAG, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND | ThemeDescription.FLAG_CHECKTAG, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, 0, new Class[]{ManageChatUserCell.class}, new String[]{"nameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{ManageChatUserCell.class}, new String[]{"statusColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteGrayText), new ThemeDescription(this.listView, 0, new Class[]{ManageChatUserCell.class}, new String[]{"statusOnlineColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteBlueText), new ThemeDescription(this.listView, 0, new Class[]{ManageChatUserCell.class}, null, new Drawable[]{Theme.avatar_savedDrawable}, null, Theme.key_avatar_text), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundRed), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundOrange), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundViolet), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundGreen), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundCyan), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundBlue), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundPink), new ThemeDescription(this.listView, 0, new Class[]{HintInnerCell.class}, new String[]{"messageTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_message), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{ManageChatTextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{ManageChatTextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayIcon), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{ManageChatTextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueButton), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{ManageChatTextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueIcon)};
    }

    public /* synthetic */ void lambda$getThemeDescriptions$16$ChatLinkActivity() {
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
