package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.JoinSheetUserCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class JoinGroupAlert extends BottomSheet {
    private TLRPC.ChatInvite chatInvite;
    private BaseFragment fragment;
    private String hash;

    public JoinGroupAlert(Context context, TLRPC.ChatInvite invite, String group, BaseFragment parentFragment) {
        String title;
        int participants_count;
        super(context, false, 0);
        setApplyBottomPadding(false);
        setApplyTopPadding(false);
        this.fragment = parentFragment;
        this.chatInvite = invite;
        this.hash = group;
        LinearLayout linearLayout = new LinearLayout(context);
        linearLayout.setOrientation(1);
        linearLayout.setClickable(true);
        setCustomView(linearLayout);
        BackupImageView avatarImageView = new BackupImageView(context);
        avatarImageView.setRoundRadius(AndroidUtilities.dp(35.0f));
        linearLayout.addView(avatarImageView, LayoutHelper.createLinear(70, 70, 49, 0, 12, 0, 0));
        if (invite.chat != null) {
            AvatarDrawable avatarDrawable = new AvatarDrawable(invite.chat);
            title = invite.chat.title;
            participants_count = invite.chat.participants_count;
            avatarImageView.setImage(ImageLocation.getForChat(invite.chat, false), "50_50", avatarDrawable, invite);
        } else {
            AvatarDrawable avatarDrawable2 = new AvatarDrawable();
            avatarDrawable2.setInfo(0, invite.title, null);
            title = invite.title;
            participants_count = invite.participants_count;
            TLRPC.PhotoSize size = FileLoader.getClosestPhotoSizeWithSize(invite.photo.sizes, 50);
            avatarImageView.setImage(ImageLocation.getForPhoto(size, invite.photo), "50_50", avatarDrawable2, invite);
        }
        TextView textView = new TextView(context);
        textView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        textView.setTextSize(1, 17.0f);
        textView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        textView.setText(title);
        textView.setSingleLine(true);
        textView.setEllipsize(TextUtils.TruncateAt.END);
        linearLayout.addView(textView, LayoutHelper.createLinear(-2, -2, 49, 10, 10, 10, participants_count > 0 ? 0 : 10));
        if (participants_count > 0) {
            TextView textView2 = new TextView(context);
            textView2.setTextSize(1, 14.0f);
            textView2.setTextColor(Theme.getColor(Theme.key_dialogTextGray3));
            textView2.setSingleLine(true);
            textView2.setEllipsize(TextUtils.TruncateAt.END);
            textView2.setText(LocaleController.formatPluralString("Members", participants_count));
            linearLayout.addView(textView2, LayoutHelper.createLinear(-2, -2, 49, 10, 4, 10, 10));
        }
        if (!invite.participants.isEmpty()) {
            RecyclerListView listView = new RecyclerListView(context);
            listView.setPadding(0, 0, 0, AndroidUtilities.dp(8.0f));
            listView.setNestedScrollingEnabled(false);
            listView.setClipToPadding(false);
            listView.setLayoutManager(new LinearLayoutManager(getContext(), 0, false));
            listView.setHorizontalScrollBarEnabled(false);
            listView.setVerticalScrollBarEnabled(false);
            listView.setAdapter(new UsersAdapter(context));
            listView.setGlowColor(Theme.getColor(Theme.key_dialogScrollGlow));
            linearLayout.addView(listView, LayoutHelper.createLinear(-2, 90, 49, 0, 0, 0, 0));
        }
        View shadow = new View(context);
        shadow.setBackgroundColor(Theme.getColor(Theme.key_dialogShadowLine));
        linearLayout.addView(shadow, new LinearLayout.LayoutParams(-1, AndroidUtilities.getShadowHeight()));
        PickerBottomLayout pickerBottomLayout = new PickerBottomLayout(context, false);
        linearLayout.addView(pickerBottomLayout, LayoutHelper.createFrame(-1, 48, 83));
        pickerBottomLayout.cancelButton.setPadding(AndroidUtilities.dp(18.0f), 0, AndroidUtilities.dp(18.0f), 0);
        pickerBottomLayout.cancelButton.setTextColor(Theme.getColor(Theme.key_dialogTextBlue2));
        pickerBottomLayout.cancelButton.setText(LocaleController.getString("Cancel", R.string.Cancel).toUpperCase());
        pickerBottomLayout.cancelButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$JoinGroupAlert$QUOmB5ZwwZN2SJcgQniJejgO1HU
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$0$JoinGroupAlert(view);
            }
        });
        pickerBottomLayout.doneButton.setPadding(AndroidUtilities.dp(18.0f), 0, AndroidUtilities.dp(18.0f), 0);
        pickerBottomLayout.doneButton.setVisibility(0);
        pickerBottomLayout.doneButtonBadgeTextView.setVisibility(8);
        pickerBottomLayout.doneButtonTextView.setTextColor(Theme.getColor(Theme.key_dialogTextBlue2));
        pickerBottomLayout.doneButtonTextView.setText(LocaleController.getString("JoinGroup", R.string.JoinGroup));
        pickerBottomLayout.doneButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$JoinGroupAlert$gDU3OoCyHNxSc2zW2Jtq7IEvth0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$3$JoinGroupAlert(view);
            }
        });
    }

    public /* synthetic */ void lambda$new$0$JoinGroupAlert(View view) {
        dismiss();
    }

    public /* synthetic */ void lambda$new$3$JoinGroupAlert(View v) {
        dismiss();
        final TLRPC.TL_messages_importChatInvite req = new TLRPC.TL_messages_importChatInvite();
        req.hash = this.hash;
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$JoinGroupAlert$otiZCMwfVxGHnRg_5ECC5ibwwCo
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$2$JoinGroupAlert(req, tLObject, tL_error);
            }
        }, 2);
    }

    public /* synthetic */ void lambda$null$2$JoinGroupAlert(final TLRPC.TL_messages_importChatInvite req, final TLObject response, final TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.Updates updates = (TLRPC.Updates) response;
            MessagesController.getInstance(this.currentAccount).processUpdates(updates, false);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$JoinGroupAlert$XDK82CwIM3nTueGUI5pixMho988
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$1$JoinGroupAlert(error, response, req);
            }
        });
    }

    public /* synthetic */ void lambda$null$1$JoinGroupAlert(TLRPC.TL_error error, TLObject response, TLRPC.TL_messages_importChatInvite req) {
        BaseFragment baseFragment = this.fragment;
        if (baseFragment == null || baseFragment.getParentActivity() == null) {
            return;
        }
        if (error != null) {
            AlertsCreator.processError(this.currentAccount, error, this.fragment, req, new Object[0]);
            return;
        }
        TLRPC.Updates updates = (TLRPC.Updates) response;
        if (!updates.chats.isEmpty()) {
            TLRPC.Chat chat = updates.chats.get(0);
            chat.left = false;
            chat.kicked = false;
            MessagesController.getInstance(this.currentAccount).putUsers(updates.users, false);
            MessagesController.getInstance(this.currentAccount).putChats(updates.chats, false);
            Bundle args = new Bundle();
            args.putInt("chat_id", chat.id);
            if (MessagesController.getInstance(this.currentAccount).checkCanOpenChat(args, this.fragment)) {
                ChatActivity chatActivity = new ChatActivity(args);
                BaseFragment baseFragment2 = this.fragment;
                baseFragment2.presentFragment(chatActivity, baseFragment2 instanceof ChatActivity);
            }
        }
    }

    private class UsersAdapter extends RecyclerListView.SelectionAdapter {
        private Context context;

        public UsersAdapter(Context context) {
            this.context = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int count = JoinGroupAlert.this.chatInvite.participants.size();
            int participants_count = JoinGroupAlert.this.chatInvite.chat != null ? JoinGroupAlert.this.chatInvite.chat.participants_count : JoinGroupAlert.this.chatInvite.participants_count;
            if (count != participants_count) {
                return count + 1;
            }
            return count;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public long getItemId(int i) {
            return i;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = new JoinSheetUserCell(this.context);
            view.setLayoutParams(new RecyclerView.LayoutParams(AndroidUtilities.dp(100.0f), AndroidUtilities.dp(90.0f)));
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            JoinSheetUserCell cell = (JoinSheetUserCell) holder.itemView;
            if (position < JoinGroupAlert.this.chatInvite.participants.size()) {
                cell.setUser(JoinGroupAlert.this.chatInvite.participants.get(position));
            } else {
                int participants_count = JoinGroupAlert.this.chatInvite.chat != null ? JoinGroupAlert.this.chatInvite.chat.participants_count : JoinGroupAlert.this.chatInvite.participants_count;
                cell.setCount(participants_count - JoinGroupAlert.this.chatInvite.participants.size());
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            return 0;
        }
    }
}
