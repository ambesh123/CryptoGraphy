#include <bits/stdc++.h>
#define inp_out_work ios::sync_with_stdio(false); cin.tie(NULL); cout.tie(NULL);
#define testCase    int T; cin>>T; while(T--)
#define debug(P) cout<<#P<<' '<<P<<endl
#define endl '\n'

using namespace std;

typedef long long ll;

const int MAXN = 10001;

int ld[MAXN]; // tracks lowest prime factor that divides a number, eg: ld[15] = 3
vector<int> primes;

//generate primes, (and record lowest prime factors for each integer in ld array)
void m_sieve(){
    for(int i = 0; i < MAXN; ++i)ld[i]=i;

    for(int i=2;i*i<MAXN;i++){
        if(ld[i]==i){
            for(int j=2*i;j<MAXN;j+=i){
                if(ld[j]==j){ld[j]=i;}
            }
        }
    }

    for(int i = 2; i < MAXN; ++i) {
      if(ld[i] == i)primes.push_back(i);
    }
}

// generates prime factors for an integer
vector<int> factors(int x){
    vector<int> ret;
    int tmp = -1;
    while(x > 1){
        tmp = ld[x];
        ret.push_back(tmp);
        while(ld[x] == tmp) x /= ld[x];
    }
    return ret;
}

// extended euclid's gcd to find inverse
template<class T>
T gcd(T a , T b , T &x , T &y){
    if(b == 0){
        x = 1  , y = 0;
        return a;
    }
    int g = gcd(b , a%b , x , y);
    T tx= y;
    T ty = x - floor(a/b)*y;
    x = tx , y = ty;
    return g;
}

// modulo power
ll modPower(ll x,ll y, ll mod){
    x%=mod;
    ll res = 1;
    while(y){
        if(y&1)res= (res*x)%mod;
        x = (x*x)%mod;
        y>>=1;
    }
    return res;
}

// randomly generates a pair of prime factors to use in public key
pair<int,int> generatePrimePairs() {
  srand(time(NULL));
  int pcnt = primes.size();
  if(pcnt < 2) return {-1, -1};

  int p = 2, q = 2;

  while(p == q) {
    p = rand() % pcnt;
    q = rand() % pcnt;

    p = primes[p];
    q = primes[q];
  }

  return {p, q};
}

// generates a random public key
int getPublicKey(int p, int q) {
  p -= 1, q -= 1;

  int LIM = max(p, q) + 1;

  vector<int> cands;

  for(int i = 2; i <= LIM; ++i) {
    if(gcd(i, p) == 1 && gcd(i, q) == 1) {
      cands.push_back(i);
    }
  }

  int pos = rand() % cands.size();

  return cands[pos];
}

// generate private key for the public key
int generatePrivateKey(ll publicKey, ll p, ll q) {
  ll x, y;
  ll tmp = (p-1) * 1LL * (q-1);

  gcd((ll)publicKey, tmp, x, y);

  while(x < 0) {
    x += tmp;
  }

  return x;
}

// encrypt message by raising power to public key
vector<ll> encryptMessage(string plainText, ll e, ll N) {
  vector<ll> cipher;

  for(char x : plainText) {
    ll xx = (ll) x;
    xx = modPower(xx, e, N);
    cipher.push_back(xx);
  }

  return cipher;
}

// decrypt message by raising power to private key
string decryptMessage(vector<ll> cipher, ll privateKey, ll N) {
  string plainText = "";

  for(ll x : cipher) {
    ll xx = modPower(x, privateKey, N);
    char cx = (char)xx;
    plainText.push_back(cx);
  }

  return plainText;
}

int main() {

  m_sieve();

  auto pq = generatePrimePairs();

  // two primes
  ll p = pq.first, q = pq.second;
  
  // public key part
  ll N = p * 1LL * q;

  // public key
  int e = getPublicKey(p, q);
  
  // private key
  int d = generatePrivateKey(e, p, q);

  // output complete public key pair
  cout<< "Public Key: (" << e <<", "<<N<<")\n";
  

  string s;
  cin>>s;

  vector<ll> cipher = encryptMessage(s, e, N);

  cout<< "Encrypted Message: ";
  for(ll x : cipher)cout<<x<<',';

  cout<<"\nDecrypting Message..\n";

  string recoveredMessage = decryptMessage(cipher, d, N);

  cout<<"Decrypted Message: " + recoveredMessage << endl;
  
}
