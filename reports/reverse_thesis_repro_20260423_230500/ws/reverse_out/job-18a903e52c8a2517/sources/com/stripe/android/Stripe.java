package com.stripe.android;

import android.os.AsyncTask;
import android.os.Build;
import com.stripe.android.exception.APIConnectionException;
import com.stripe.android.exception.APIException;
import com.stripe.android.exception.AuthenticationException;
import com.stripe.android.exception.CardException;
import com.stripe.android.exception.InvalidRequestException;
import com.stripe.android.exception.StripeException;
import com.stripe.android.model.Card;
import com.stripe.android.model.Token;
import com.stripe.android.net.RequestOptions;
import com.stripe.android.net.StripeApiHandler;
import com.stripe.android.util.StripeNetworkUtils;
import java.util.concurrent.Executor;

/* JADX INFO: loaded from: classes3.dex */
public class Stripe {
    private String defaultPublishableKey;
    TokenCreator tokenCreator = new TokenCreator() { // from class: com.stripe.android.Stripe.1
        @Override // com.stripe.android.Stripe.TokenCreator
        public void create(final Card card, final String publishableKey, Executor executor, final TokenCallback callback) {
            AsyncTask<Void, Void, ResponseWrapper> task = new AsyncTask<Void, Void, ResponseWrapper>() { // from class: com.stripe.android.Stripe.1.1
                /* JADX INFO: Access modifiers changed from: protected */
                /* JADX WARN: Multi-variable type inference failed */
                @Override // android.os.AsyncTask
                public ResponseWrapper doInBackground(Void... voidArr) {
                    Exception exc = null;
                    Object[] objArr = 0;
                    Object[] objArr2 = 0;
                    Object[] objArr3 = 0;
                    try {
                        return new ResponseWrapper(StripeApiHandler.createToken(StripeNetworkUtils.hashMapFromCard(card), RequestOptions.builder(publishableKey).build()), exc);
                    } catch (StripeException e) {
                        return new ResponseWrapper(objArr2 == true ? 1 : 0, e);
                    }
                }

                /* JADX INFO: Access modifiers changed from: protected */
                @Override // android.os.AsyncTask
                public void onPostExecute(ResponseWrapper result) {
                    Stripe.this.tokenTaskPostExecution(result, callback);
                }
            };
            Stripe.this.executeTokenTask(executor, task);
        }
    };

    interface TokenCreator {
        void create(Card card, String str, Executor executor, TokenCallback tokenCallback);
    }

    public Stripe() {
    }

    public Stripe(String publishableKey) throws AuthenticationException {
        setDefaultPublishableKey(publishableKey);
    }

    public void createToken(Card card, TokenCallback callback) {
        createToken(card, this.defaultPublishableKey, callback);
    }

    public void createToken(Card card, String publishableKey, TokenCallback callback) {
        createToken(card, publishableKey, null, callback);
    }

    public void createToken(Card card, Executor executor, TokenCallback callback) {
        createToken(card, this.defaultPublishableKey, executor, callback);
    }

    public void createToken(Card card, String publishableKey, Executor executor, TokenCallback callback) {
        try {
            if (card == null) {
                throw new RuntimeException("Required Parameter: 'card' is required to create a token");
            }
            if (callback == null) {
                throw new RuntimeException("Required Parameter: 'callback' is required to use the created token and handle errors");
            }
            validateKey(publishableKey);
            this.tokenCreator.create(card, publishableKey, executor, callback);
        } catch (AuthenticationException e) {
            callback.onError(e);
        }
    }

    public Token createTokenSynchronous(Card card) throws CardException, APIConnectionException, AuthenticationException, InvalidRequestException, APIException {
        return createTokenSynchronous(card, this.defaultPublishableKey);
    }

    public Token createTokenSynchronous(Card card, String publishableKey) throws CardException, APIConnectionException, AuthenticationException, InvalidRequestException, APIException {
        validateKey(publishableKey);
        RequestOptions requestOptions = RequestOptions.builder(publishableKey).build();
        return StripeApiHandler.createToken(StripeNetworkUtils.hashMapFromCard(card), requestOptions);
    }

    public void setDefaultPublishableKey(String publishableKey) throws AuthenticationException {
        validateKey(publishableKey);
        this.defaultPublishableKey = publishableKey;
    }

    private void validateKey(String publishableKey) throws AuthenticationException {
        if (publishableKey == null || publishableKey.length() == 0) {
            throw new AuthenticationException("Invalid Publishable Key: You must use a valid publishable key to create a token.  For more info, see https://stripe.com/docs/stripe.js.", null, 0);
        }
        if (publishableKey.startsWith("sk_")) {
            throw new AuthenticationException("Invalid Publishable Key: You are using a secret key to create a token, instead of the publishable one. For more info, see https://stripe.com/docs/stripe.js", null, 0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void tokenTaskPostExecution(ResponseWrapper result, TokenCallback callback) {
        if (result.token != null) {
            callback.onSuccess(result.token);
        } else if (result.error != null) {
            callback.onError(result.error);
        } else {
            callback.onError(new RuntimeException("Somehow got neither a token response or an error response"));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void executeTokenTask(Executor executor, AsyncTask<Void, Void, ResponseWrapper> task) {
        if (executor != null && Build.VERSION.SDK_INT > 11) {
            task.executeOnExecutor(executor, new Void[0]);
        } else {
            task.execute(new Void[0]);
        }
    }

    private class ResponseWrapper {
        final Exception error;
        final Token token;

        private ResponseWrapper(Token token, Exception error) {
            this.error = error;
            this.token = token;
        }
    }
}
