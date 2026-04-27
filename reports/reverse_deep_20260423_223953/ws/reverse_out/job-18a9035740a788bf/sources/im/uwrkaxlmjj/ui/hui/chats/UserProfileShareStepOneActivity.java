package im.uwrkaxlmjj.ui.hui.chats;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Color;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.utils.ShapeUtils;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.DialogsActivity;
import im.uwrkaxlmjj.ui.NewContactActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.XAlertDialog;
import im.uwrkaxlmjj.ui.adapters.DialogsAdapter;
import im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ColorTextView;
import im.uwrkaxlmjj.ui.components.JoinGroupAlert;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.StickersAlert;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.contacts.ShareCardSelectContactActivity;
import im.uwrkaxlmjj.ui.hui.decoration.TopDecorationWithSearch;
import im.uwrkaxlmjj.ui.hviews.MryEmptyView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialog;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import java.util.ArrayList;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class UserProfileShareStepOneActivity extends BaseSearchViewFragment implements NotificationCenter.NotificationCenterDelegate {
    private static boolean CanMultiSelect = false;
    private static final int STEP_ONE = 0;
    private static final int STEP_TWO = 1;
    private ArrayList<Object> data;
    private ArrayList<Object> dataList;
    private MryEmptyView emptyView;
    protected long lid;
    private DialogsAdapter mAdapter;
    private AdapterMultiSelect mAdapterMultiSelect;
    private DialogsSearchAdapter mSearchAdapter;
    private int mStep;
    private int mUserId;
    private RecyclerListView rv;
    private RecyclerListView rvMultiSelect;
    private ArrayList<Object> searchData;
    private FrameLayout searchLayout;

    public UserProfileShareStepOneActivity(Bundle args) {
        super(args);
        this.data = new ArrayList<>();
        this.searchData = new ArrayList<>();
        this.dataList = null;
        this.lid = 0L;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        if (getArguments() != null) {
            this.mUserId = getArguments().getInt("user_id");
            this.mStep = getArguments().getInt("step");
        }
        getNotificationCenter().addObserver(this, NotificationCenter.dialogsNeedReload);
        getNotificationCenter().addObserver(this, NotificationCenter.updateInterfaces);
        getNotificationCenter().addObserver(this, NotificationCenter.encryptedChatUpdated);
        getNotificationCenter().addObserver(this, NotificationCenter.contactsDidLoad);
        getNotificationCenter().addObserver(this, NotificationCenter.appDidLogout);
        getNotificationCenter().addObserver(this, NotificationCenter.openedChatChanged);
        if (!DialogsActivity.dialogsLoaded[this.currentAccount]) {
            getMessagesController().loadGlobalNotificationsSettings();
            getMessagesController().loadDialogs(0, 0, 100, true);
            getMessagesController().loadHintDialogs();
            getContactsController().checkInviteText();
            getMediaDataController().loadRecents(2, false, true, false);
            getMediaDataController().checkFeaturedStickers();
            DialogsActivity.dialogsLoaded[this.currentAccount] = true;
        }
        getMessagesController().loadPinnedDialogs(0, 0L, null);
        this.mblnMove = false;
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        getNotificationCenter().removeObserver(this, NotificationCenter.dialogsNeedReload);
        getNotificationCenter().removeObserver(this, NotificationCenter.updateInterfaces);
        getNotificationCenter().removeObserver(this, NotificationCenter.encryptedChatUpdated);
        getNotificationCenter().removeObserver(this, NotificationCenter.contactsDidLoad);
        getNotificationCenter().removeObserver(this, NotificationCenter.appDidLogout);
        getNotificationCenter().removeObserver(this, NotificationCenter.openedChatChanged);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        FrameLayout container = new FrameLayout(context);
        this.fragmentView = container;
        container.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initActionBar();
        initEmptyView(context);
        initListRv(context);
        super.createView(context);
        return this.fragmentView;
    }

    private void initActionBar() {
        if (this.mStep == 0) {
            this.actionBar.setTitle(LocaleController.getString(R.string.ShareFriendBusinessCard));
            this.actionBar.setBackTitle(LocaleController.getString(R.string.Cancel));
        } else {
            this.actionBar.setTitle(LocaleController.getString(R.string.SelectNewContactUser));
            this.actionBar.setBackButtonImage(R.id.ic_back);
        }
        this.actionBar.setAllowOverlayTitle(false);
        this.actionBar.setCastShadows(false);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.chats.UserProfileShareStepOneActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    UserProfileShareStepOneActivity.this.finishFragment(true);
                }
            }
        });
        this.actionBar.getBackTitleTextView().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$UserProfileShareStepOneActivity$ubOyQbfibbMUxg317POdGJ6egNI
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initActionBar$0$UserProfileShareStepOneActivity(view);
            }
        });
    }

    public /* synthetic */ void lambda$initActionBar$0$UserProfileShareStepOneActivity(View v) {
        finishFragmentFromUp(true);
    }

    private void getRecentlyContacterList() {
        ArrayList<TLRPC.Dialog> array = DialogsActivity.getDialogsArray(this.currentAccount, 3, 0, false);
        filterList(array);
    }

    protected void filterList(ArrayList<TLRPC.Dialog> array) {
        if (array != null) {
            for (TLRPC.Dialog dialog : array) {
                TLRPC.User user = null;
                TLRPC.Chat chat = null;
                long dialogId = dialog.id;
                if (dialogId != 0) {
                    int lower_id = (int) dialogId;
                    if (lower_id != 0) {
                        if (lower_id < 0) {
                            chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(-lower_id));
                        } else {
                            user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(lower_id));
                        }
                    }
                }
                if (user != null) {
                    if (user.id != UserConfig.getInstance(this.currentAccount).getCurrentUser().id && user.id != 777000) {
                        this.data.add(user);
                    }
                } else if (chat != null && ChatObject.canSendMessages(chat)) {
                    if (chat.default_banned_rights.embed_links && ChatObject.hasAdminRights(chat)) {
                        this.data.add(chat);
                    } else if (!chat.default_banned_rights.embed_links) {
                        this.data.add(chat);
                    }
                }
            }
        }
        this.dataList = this.data;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment
    protected MrySearchView getSearchView() {
        FrameLayout frameLayout = new FrameLayout(getParentActivity());
        this.searchLayout = frameLayout;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        ((FrameLayout) this.fragmentView).addView(this.searchLayout, LayoutHelper.createFrame(-1, 55.0f));
        this.searchView = new MrySearchView(getParentActivity());
        this.searchView.setHintText(LocaleController.getString("Search", R.string.Search));
        this.searchView.setCancelTextColor(Color.parseColor("#999999"));
        this.searchLayout.addView(this.searchView, LayoutHelper.createFrame(-1.0f, 35.0f, 17, 10.0f, 10.0f, 10.0f, 10.0f));
        return this.searchView;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onTextChange(String value) {
        super.onTextChange(value);
        if (!TextUtils.isEmpty(value)) {
            this.searchData.clear();
            for (Object obj : this.data) {
                if (obj instanceof TLRPC.User) {
                    TLRPC.User user = (TLRPC.User) obj;
                    if (user.first_name.contains(value)) {
                        this.searchData.add(user);
                    }
                } else if (obj instanceof TLRPC.Chat) {
                    TLRPC.Chat chat = (TLRPC.Chat) obj;
                    if (chat.title.contains(value)) {
                        this.searchData.add(chat);
                    }
                }
            }
            this.dataList = this.searchData;
            if (this.rv.getAdapter() != null) {
                this.rv.getAdapter().notifyDataSetChanged();
                return;
            }
            return;
        }
        this.dataList = this.data;
        if (this.rv.getAdapter() != null) {
            this.rv.getAdapter().notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onSearchCollapse() {
        super.onSearchCollapse();
        this.dataList = this.data;
        if (this.rv.getAdapter() != null) {
            this.rv.getAdapter().notifyDataSetChanged();
        }
    }

    private void initEmptyView(Context context) {
        MryEmptyView mryEmptyView = new MryEmptyView(context);
        this.emptyView = mryEmptyView;
        mryEmptyView.attach((ViewGroup) this.fragmentView);
    }

    private void initListRv(Context context) {
        getRecentlyContacterList();
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.rv = recyclerListView;
        recyclerListView.setTag("rv_list");
        this.rv.setOverScrollMode(2);
        this.rv.setLayoutManager(new LinearLayoutManager(context));
        this.rv.addItemDecoration(new TopDecorationWithSearch());
        this.rv.setVerticalScrollBarEnabled(false);
        this.rv.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.rv.setInstantClick(true);
        ((FrameLayout) this.fragmentView).addView(this.rv, LayoutHelper.createFrame(-1, -2, AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0));
        this.rv.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$UserProfileShareStepOneActivity$yIfxeVCLh-D89w2n85ljK9TURrs
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initListRv$2$UserProfileShareStepOneActivity(view, i);
            }
        });
        this.rv.setAdapter(new Adapter());
    }

    public /* synthetic */ void lambda$initListRv$2$UserProfileShareStepOneActivity(View view, int position) {
        long dialog_id;
        RecyclerListView recyclerListView = this.rv;
        if (recyclerListView == null || recyclerListView.getAdapter() == null || getParentActivity() == null) {
            return;
        }
        RecyclerView.Adapter adapter = this.rv.getAdapter();
        DialogsAdapter dialogsAdapter = this.mAdapter;
        if (adapter != dialogsAdapter) {
            DialogsSearchAdapter dialogsSearchAdapter = this.mSearchAdapter;
            if (adapter != dialogsSearchAdapter) {
                dialog_id = 0;
            } else {
                Object obj = dialogsSearchAdapter.getItem(position);
                this.mSearchAdapter.isGlobalSearch(position);
                if (obj instanceof TLRPC.User) {
                    dialog_id = ((TLRPC.User) obj).id;
                } else if (obj instanceof TLRPC.Chat) {
                    dialog_id = -((TLRPC.Chat) obj).id;
                } else if (obj instanceof TLRPC.EncryptedChat) {
                    dialog_id = ((long) ((TLRPC.EncryptedChat) obj).id) << 32;
                } else if (obj instanceof MessageObject) {
                    MessageObject messageObject = (MessageObject) obj;
                    dialog_id = messageObject.getDialogId();
                    messageObject.getId();
                    DialogsSearchAdapter dialogsSearchAdapter2 = this.mSearchAdapter;
                    dialogsSearchAdapter2.addHashtagsFromMessage(dialogsSearchAdapter2.getLastSearchString());
                } else {
                    if (obj instanceof String) {
                        String str = (String) obj;
                        if (this.mSearchAdapter.isHashtagSearch()) {
                            this.actionBar.openSearchField(str, false);
                        } else if (!str.equals("section")) {
                            NewContactActivity activity = new NewContactActivity();
                            activity.setInitialPhoneNumber(str);
                            presentFragment(activity);
                        }
                    }
                    dialog_id = 0;
                }
            }
        } else {
            TLObject object = dialogsAdapter.getItem(position);
            if (object instanceof TLRPC.User) {
                dialog_id = ((TLRPC.User) object).id;
            } else if (object instanceof TLRPC.Dialog) {
                TLRPC.Dialog dialog = (TLRPC.Dialog) object;
                if (dialog instanceof TLRPC.TL_dialogFolder) {
                    if (this.actionBar.isActionModeShowed()) {
                        return;
                    }
                    TLRPC.TL_dialogFolder dialogFolder = (TLRPC.TL_dialogFolder) dialog;
                    Bundle args = new Bundle();
                    args.putInt("folderId", dialogFolder.folder.id);
                    presentFragment(new MryDialogsActivity(args));
                    return;
                }
                long dialog_id2 = dialog.id;
                dialog_id = dialog_id2;
            } else if (object instanceof TLRPC.TL_recentMeUrlChat) {
                dialog_id = -((TLRPC.TL_recentMeUrlChat) object).chat_id;
            } else if (object instanceof TLRPC.TL_recentMeUrlUser) {
                dialog_id = ((TLRPC.TL_recentMeUrlUser) object).user_id;
            } else if (object instanceof TLRPC.TL_recentMeUrlChatInvite) {
                TLRPC.TL_recentMeUrlChatInvite chatInvite = (TLRPC.TL_recentMeUrlChatInvite) object;
                TLRPC.ChatInvite invite = chatInvite.chat_invite;
                if ((invite.chat == null && (!invite.channel || invite.megagroup)) || (invite.chat != null && (!ChatObject.isChannel(invite.chat) || invite.chat.megagroup))) {
                    String hash = chatInvite.url;
                    int index = hash.indexOf(47);
                    if (index > 0) {
                        hash = hash.substring(index + 1);
                    }
                    showDialog(new JoinGroupAlert(getParentActivity(), invite, hash, this));
                    return;
                }
                if (invite.chat != null) {
                    long dialog_id3 = -invite.chat.id;
                    dialog_id = dialog_id3;
                } else {
                    return;
                }
            } else {
                if (!(object instanceof TLRPC.TL_recentMeUrlStickerSet)) {
                    if (object instanceof TLRPC.TL_recentMeUrlUnknown) {
                        return;
                    } else {
                        return;
                    }
                }
                TLRPC.StickerSet stickerSet = ((TLRPC.TL_recentMeUrlStickerSet) object).set.set;
                TLRPC.TL_inputStickerSetID set = new TLRPC.TL_inputStickerSetID();
                set.id = stickerSet.id;
                set.access_hash = stickerSet.access_hash;
                showDialog(new StickersAlert(getParentActivity(), this, set, null, null));
                return;
            }
        }
        if (position == 0) {
            ShareCardSelectContactActivity activity2 = new ShareCardSelectContactActivity(null);
            activity2.setDelegate(new ShareCardSelectContactActivity.ContactsActivityDelegate() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$UserProfileShareStepOneActivity$aIWO-ANaaf6x8bCJ-o3En07GC84
                @Override // im.uwrkaxlmjj.ui.hui.contacts.ShareCardSelectContactActivity.ContactsActivityDelegate
                public final void didSelectContact(TLRPC.User user) {
                    this.f$0.lambda$null$1$UserProfileShareStepOneActivity(user);
                }
            });
            presentFragment(activity2);
        }
        if (position > 1) {
            Object obj2 = this.dataList.get(position - 2);
            if (obj2 instanceof TLRPC.User) {
                this.lid = ((TLRPC.User) obj2).id;
            } else {
                this.lid = ((TLRPC.Chat) obj2).id * (-1);
            }
            showDialog(obj2);
        }
        if (dialog_id == 0) {
        }
    }

    public /* synthetic */ void lambda$null$1$UserProfileShareStepOneActivity(TLRPC.User user) {
        this.lid = user.id;
        showDialog(user);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
    }

    private void showDialog(Object obj) {
        XDialog.Builder builder = new XDialog.Builder(getParentActivity(), 15);
        View v = LayoutInflater.from(getParentActivity()).inflate(R.layout.dialog_share_contact, (ViewGroup) null);
        final EditText etContent = (EditText) v.findViewById(R.attr.et_content);
        BackupImageView ivHead = (BackupImageView) v.findViewById(R.attr.iv_head_img);
        ivHead.setRoundRadius(AndroidUtilities.dp(7.5f));
        TextView tvName = (TextView) v.findViewById(R.attr.tv_name);
        TextView tvCard = (TextView) v.findViewById(R.attr.tv_card);
        AvatarDrawable avatarDrawable = new AvatarDrawable();
        if (obj != null) {
            if (obj instanceof TLRPC.User) {
                TLRPC.User user = (TLRPC.User) obj;
                avatarDrawable.setInfo(user);
                ivHead.setImage(ImageLocation.getForUser(user, false), "50_50", avatarDrawable, user);
                tvName.setText(user.first_name);
                etContent.setHint(LocaleController.getString(R.string.share_contact_content));
            } else {
                TLRPC.Chat chat = (TLRPC.Chat) obj;
                avatarDrawable.setInfo(chat);
                ivHead.setImage(ImageLocation.getForChat(chat, false), "50_50", avatarDrawable, chat);
                tvName.setText(chat.title);
                etContent.setHint(LocaleController.getString(R.string.share_contact_content_group));
            }
        }
        tvCard.setText(String.format("[%s]%s", LocaleController.getString(R.string.share_contact_person_card), MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.mUserId)).first_name));
        etContent.setBackground(ShapeUtils.create(Color.parseColor("#F6F7F9"), AndroidUtilities.dp(8.0f)));
        builder.setView(v);
        builder.setPositiveButton(LocaleController.getString("Send", R.string.Send), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$UserProfileShareStepOneActivity$CT_pMvWeXqiJPRVLAu3R6lMnJYU
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showDialog$3$UserProfileShareStepOneActivity(etContent, dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        XDialog dialog = builder.create();
        dialog.show();
    }

    public /* synthetic */ void lambda$showDialog$3$UserProfileShareStepOneActivity(EditText etContent, DialogInterface dialogInterface, int i) {
        int currentConnectionState = ConnectionsManager.getInstance(UserConfig.selectedAccount).getConnectionState();
        if (currentConnectionState == 2 || currentConnectionState == 1) {
            ToastUtils.show((CharSequence) LocaleController.getString(R.string.visual_call_no_network));
        } else {
            startSendCard(etContent.getText().toString());
        }
    }

    private void startSendCard(String strContent) {
        final XAlertDialog progressDialog = new XAlertDialog(getParentActivity(), 4);
        progressDialog.setLoadingText(LocaleController.getString(R.string.ApplySending));
        SendMessagesHelper.getInstance(this.currentAccount).sendMessage(MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.mUserId)), this.lid, (MessageObject) null, (TLRPC.ReplyMarkup) null, (HashMap<String, String>) null, true, 0);
        if (!TextUtils.isEmpty(strContent)) {
            SendMessagesHelper.getInstance(this.currentAccount).sendMessage(strContent, this.lid, null, null, true, null, null, null, true, 0);
        }
        progressDialog.show();
        progressDialog.setLoadingImage(getParentActivity().getResources().getDrawable(R.id.ic_apply_send_done), AndroidUtilities.dp(30.0f), AndroidUtilities.dp(20.0f));
        progressDialog.setLoadingText(LocaleController.getString(R.string.ApplySent));
        progressDialog.setCanCacnel(false);
        this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$UserProfileShareStepOneActivity$F9br96DUJGnOfeFMHZbcsGF3fk0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$startSendCard$4$UserProfileShareStepOneActivity(progressDialog);
            }
        }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
    }

    public /* synthetic */ void lambda$startSendCard$4$UserProfileShareStepOneActivity(XAlertDialog progressDialog) {
        progressDialog.dismiss();
        finishFragmentFromUp(true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        if (this.searchView != null && this.searchView.isSearchFieldVisible()) {
            this.searchView.closeSearchField();
        }
    }

    private class Adapter extends RecyclerListView.SelectionAdapter {
        private ArrayList<Long> selectedDialogs;

        private Adapter() {
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 1) {
                MryTextView tv = new MryTextView(UserProfileShareStepOneActivity.this.getParentActivity());
                tv.setTextColor(Color.parseColor("#999999"));
                tv.setTextSize(13.0f);
                tv.setText(LocaleController.getString(R.string.share_contact_recently_chat));
                view = new FrameLayout(UserProfileShareStepOneActivity.this.getParentActivity());
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(35.0f)));
                ((FrameLayout) view).addView(tv, LayoutHelper.createFrame(-2.0f, -2.0f, 16, 0.0f, 0.0f, 0.0f, 0.0f));
            } else if (viewType == 0) {
                view = new FrameLayout(UserProfileShareStepOneActivity.this.getParentActivity());
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(55.0f)));
                view.setBackground(Theme.createRoundRectDrawable(7.5f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                MryTextView tv2 = new MryTextView(UserProfileShareStepOneActivity.this.getParentActivity());
                tv2.setTextColor(Theme.key_windowBackgroundWhiteBlackText);
                tv2.setTextSize(14.0f);
                tv2.setText(LocaleController.getString(R.string.SelectNewContactUserToSend));
                ((FrameLayout) view).addView(tv2, LayoutHelper.createFrame(-2.0f, -2.0f, 16, 12.0f, 0.0f, 0.0f, 0.0f));
                ImageView iv = new ImageView(UserProfileShareStepOneActivity.this.getParentActivity());
                iv.setImageResource(R.id.icon_arrow_right);
                ((FrameLayout) view).addView(iv, LayoutHelper.createFrame(7.0f, 12.0f, 21, 10.0f, 0.0f, 12.0f, 0.0f));
            } else {
                view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_recently_contacter, parent, false);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(65.0f)));
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            holder.getItemViewType();
            if (position > 1) {
                AvatarDrawable avatarDrawable = new AvatarDrawable();
                ColorTextView tvCount = (ColorTextView) holder.itemView.findViewById(R.attr.tv_count);
                ColorTextView tvName = (ColorTextView) holder.itemView.findViewById(R.attr.tv_name);
                ColorTextView tvPersonName = (ColorTextView) holder.itemView.findViewById(R.attr.tv_person_name);
                ColorTextView tvState = (ColorTextView) holder.itemView.findViewById(R.attr.tv_state);
                BackupImageView iv_Header = (BackupImageView) holder.itemView.findViewById(R.attr.iv_head_img);
                iv_Header.setRoundRadius(AndroidUtilities.dp(7.5f));
                Object obj = UserProfileShareStepOneActivity.this.dataList.get(position - 2);
                if (obj != null) {
                    if (obj instanceof TLRPC.User) {
                        TLRPC.User user = (TLRPC.User) obj;
                        avatarDrawable.setInfo(user);
                        iv_Header.setImage(ImageLocation.getForUser(user, false), "50_50", avatarDrawable, user);
                        tvPersonName.setText(user.first_name);
                        boolean[] booleans = {false};
                        tvState.setText(LocaleController.formatUserStatusNew(UserProfileShareStepOneActivity.this.currentAccount, user, booleans));
                        if (booleans[0]) {
                            tvState.setTextColor(Color.parseColor("#42B71E"));
                        } else {
                            tvState.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2));
                        }
                        tvCount.setText("");
                        tvName.setText("");
                        return;
                    }
                    if (obj instanceof TLRPC.Chat) {
                        TLRPC.Chat chat = (TLRPC.Chat) obj;
                        avatarDrawable.setInfo(chat);
                        iv_Header.setImage(ImageLocation.getForChat(chat, false), "50_50", avatarDrawable, chat);
                        tvName.setText(chat.title);
                        tvPersonName.setText("");
                        tvState.setText("");
                        tvCount.setText(String.format("(%s)", LocaleController.formatString("share_contact_person", R.string.share_contact_person, Integer.valueOf(chat.participants_count))));
                    }
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int dialogsCount = UserProfileShareStepOneActivity.this.dataList.size();
            if (dialogsCount == 0 && MessagesController.getInstance(UserProfileShareStepOneActivity.this.currentAccount).isLoadingDialogs(0)) {
                return 0;
            }
            return dialogsCount + 2;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            return position;
        }
    }

    private class AdapterMultiSelect extends RecyclerListView.SelectionAdapter {
        private AdapterMultiSelect() {
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            return null;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return 0;
        }
    }
}
