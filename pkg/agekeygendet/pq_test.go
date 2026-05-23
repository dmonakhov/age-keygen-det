package agekeygendet

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// pqTestVectors hold the static expected outputs for known seeds.
// PQ recipients are ~1959 characters; we store the full strings as
// a permanent contract once locked.
//
// To (re-)generate: run `go test -run TestDerivePQSnapshot -v` and
// copy the printed values.
var pqTestVectors = []struct {
	name          string
	seedHex       string
	wantIdentity  string
	wantRecipient string
}{
	{
		name:          "zero-seed",
		seedHex:       "0000000000000000000000000000000000000000000000000000000000000000",
		wantIdentity:  "AGE-SECRET-KEY-PQ-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQAE0WQE",
		wantRecipient: "age1pq185sf7ut82tmyprnl3x7wa7t6cwy9xqz9xaujwezw7prvpf72a9uv3pq6qye64383uxnsyunh7ecjr8843wza98y0asywm4pju7r68nuexmlqqf4pz09ea7cawg2qf9f8hl3pg84pwzczjjjegqatpnskwc9gh254hq3uhw92ehxp0mejwafz83u3ud6qzcu5r7dm8a3ng6l0rszscv0extrzwx2zntl3fs4agw9tzdd766fd2mrhcpxthl7kxdd40qcck5fhw85yk982sgfxy9qu5qrvew9ly5q25yqgju8jzml87xhrgyj652gyjtqxngvfyg4dcv30jajfca3v05cj3tfmkfn8juwsw3qpf0pmvaz9e0xsk0n7560mrjulnse3l96g0yspsu5jjfksfgj6yeg2h02ynq4mps7xxq07dfsnxrfymz3uwqsac03njtre5yumxasnhwn852vy9xzs0wz2f4s7auv2e7uhnted8892fsxmg5fcz56e6ahux7xx8fl57vznk9ck35pzrncv9mk92996yd0cr5zdvlpmt3gcp9y3wecuy6nuq3j9w5eucv5ygkqjw7sravr9c3ff5au6nfv83u42c0upmw0d8kxfx3tfwpvvhwvax7du59kclkmp6y5evqus2frerwwnu5qmjq9aregq9cy4hcrvy0clkgf0tqqlyjmt9rqv2jfay3ks923flgavl0s4438zzt4skmmfawl2ykdzwqa2fscgyf9akaquvhr6t49l77yz09g8h0l9z0t65455u7euma32kdjryapdfgx2nv6hpwn5975q8drf38y9ym49smxylsegvc2rk7tqzujl54zl62qtgpznqvvthsehzx28zzmdwjl25c57kx9rd22nkav3tt5knxd6tjyvm3t2g6rpc5qr9jdkxz7vz3z6xzrcj7du2k3vp92m7wvmyvfq8wgvv5dk4lswys4454pj2zc59aefrmt48kqkpx8hjyes92xwj9jpw9nz848u9tr8w2497dn5qs4hcjsc5gvx9zdy438zqpm5t9k2q0n8nrr4q6ucfxvak6kpgfvxhts8n8c7wahe75j8m3t5mp2kmhumh0zv5djryc690a6zfqqs6ck5xyfxsds2aj6fq269p0eq2rkt3wn6j2pq6geltg2w6vfztgw30jn0r85ztz2vlvvq0kfze0tqwcgnf0jpj9zteaeqqcmx53rqzdadjymvzylst665csy4yrkuwtjp2rxr5f9slqv7asgmh5vu49j9kzqs5c954z57nsu42wt2zefe2kcy0085lxzr8snjxmzhp46lsz0yf2hjmsekvkpxx5v89s5nx59txfz33jxqeq94y8yqeqd9d0wfdzjk2qc44qcv3wch2vkx9nxz8vw5vsfvy44jyn75vazfrqp4q8gpgvf9cathywtgn9jmdxyu54shj0q0shrz48snfp76zanz5uvgcu93qs9x0m2v87z7wn3kjxpzlwtrzntpxnlx5cnt8jlpgcwk9fa4wwevca2hnlaz99n7xm8t9gd2pdccwk3zw5whq6mje20v6rypqzks4fvqpxjus0llayt4ne465z5ngkhenl3md9gfm0yyqv5x3pz2k0m9hvwl304d7djy9eywxwwfvupr55j5z92yc7y69uzd4ngxllhhsvpzzpzshyclddxr924nfgl4yc9czr6vn22xls3d8w4t42qt4rve2htdcd0gvzd5y445stxunkyh0sdy0g65ulzj0ld3vuhpv6ghh9wdvdgcyqnpm24nv8u29h9mysx9t27k4qg9u553ksnm2ekhx8ntwpr3388lyrvtzg8qk0njguk3kqyxsy3qplfknr3r7phy7nsghw65eshkxcqm07z6enlw5tghjexxddgefv8s3cv9r8a2acv5u0qs9q3svgtmer93",
	},
	{
		name:          "all-ones-seed",
		seedHex:       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		wantIdentity:  "AGE-SECRET-KEY-PQ-1LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLSL8VLFW",
		wantRecipient: "age1pq1h42gauqjcpmyhzmxs45vjujh4jnmvcn5yn9qw4t0skshu3pu672pufmvx596s87vveuv7d5rkkerr2g4960wpfdt2e63pwqv28c9lrn30ls9v3uenzarpgzrk09zrz6evq800xx42dw3qwqweav5grpntenw28p47g46gk2scfarcntuzgce5jdchytwnfex7c66c9ky0rquxktwzcu8je7w0ryjfznk9mu055xn0gz00v5ac733p3hkq4l6kcjn4954f6chl9ygsjq62xs0ry4p53vnd9xxludsxvnm88jjvewh0fzsxkutxvvee3cgqgcj2hnp8jx89wrlz6qz243xhrsp2yd4guz6mccj30s4kme2fv2gngyhjpa2wss8s4dknfpgpeerwg3w8j6u3qpr46tn3cv29mrxv8tmw2zvsuryhxu43rx2982xk0zcgz0ufz6579c45s78hus0x9p4afcyf92yn8ntrrs8w0ygwpe6uguuj52nu02h4jf20pqnskvgdfuw8vcvnneynrkjnntzwssdsvqfppsd9rgnlx54c3n03fual8rxndnl3xeqv6hxzawt2hgs2a0wlscsrq4e82sxema0grfqhfu5292mjts5uhutwc4lx5hsuxmklcu6wr9555accl94pqt56f28rc436lcs6zh8ffw38w2t7ez6h7d90zzfjgrztyl9nwlylx3at4dtyeg5j6gep5zjnfgtj3w7r95amp92y8dezza04fcg66qj72ac674v2etqf473jyjywpg57eeneruxk978xfk3dpuqzpecf4znmdqz9e0vcnhexv806zkahvwzj299kfcpff8vdr5xsdxtj5c9rq4xf7y692we4dsdzuykg2g83mtmx4e8yxn7e3c60yah9z7fhlk9755jrwyjf058z0r3pmyvr65gvc7ywawpsz634d8zfxguerchnwl5tvtthdz629qsjamuppwfqzg9j85dxhtk4g83d8qsgk72ycvpsqf5xg5zj5kxlv6qw5f6vgssp64nqaxydw6unavhvmqex9trf8nhhnsyaj9w4t957e33cxazgf7e93yv3p4uys25y2tylkzketz23xqp3pl29w9wpda4elypwzth00c27pg5hvy5a22e5fzkhwp74snazy4u7srkwmv5z0szpqtlj6hfvpxnvq9g9ztxutxvv0dwcp7ykurye4pu282jl6xy4pw0w5ad9gam5jtxup2g6wxrwzg5qx22kujdrjqg7uy56y0kelvcffmtk34h9pye933v933pp04pj6lq695h2rzu8lf3w2xsx2z5wgf6wftqal9xyqwv69qxvx622ykwqggcpez8u2czcg6zw5rufy4dqlyvnt9p3j3nmg82y2x35u6tezx54jgjsvrpx8ag8a4tkujsrqsprkxz9xsvam5ff2fxwk6wxdqdy6c3srgzdr0p2gryz8nhevuslqpfhk4296gxglqwhrgv2dftsy5a4tq47wv5gx7nfdd9tw30zw44lzxqfkgueps8580h2zcskws94gscgcujjln3k8efqs7gyzfqf73xv7g2wcfk5sqq2z5q5pj3hug8ekd3sv7ntx6jfwn2dff52zjxu8wnqy37sn4wpsnrtd2cl9z3psytzxk58rut6wppuqv3mdnca0e4yfapjk3nqasuwwswgl52dvgntg969q2y2ecp677ylj7t99wc9lrzcyzpjkyagpayxw4c4n5svcfx2p5lq5djvf4f9tg80xpn9yulx3tv79rn444kqjd8cdayctgt9v20gysalqzcmguqewmpqjy4w4v86ex88puq3t08lyw302kpj207l58euvklq474y0r33vl8smxwfp6emwau86038eqtqdvcjeezky08emy9ekputvnyh52gwuug27ahdlagxcj5gjzu",
	},
}

func TestDerivePQ(t *testing.T) {
	for _, tc := range pqTestVectors {
		t.Run(tc.name, func(t *testing.T) {
			seed, err := hex.DecodeString(tc.seedHex)
			if err != nil {
				t.Fatalf("decode seed: %v", err)
			}

			gotID, gotRcpt, err := derivePQ(seed)
			if err != nil {
				t.Fatalf("derivePQ: %v", err)
			}

			if !strings.HasPrefix(gotID, "AGE-SECRET-KEY-PQ-1") {
				t.Errorf("identity missing HRP: prefix=%q", gotID[:30])
			}
			if !strings.HasPrefix(gotRcpt, "age1pq1") {
				t.Errorf("recipient missing HRP: prefix=%q", gotRcpt[:16])
			}
			// Recipient length sanity: 1216-byte payload + HRP + checksum
			// is approximately 1959 chars.
			if len(gotRcpt) < 1950 || len(gotRcpt) > 1970 {
				t.Errorf("recipient length unexpected: %d (want ~1959)", len(gotRcpt))
			}
			// Identity is the 32-byte seed bech32-encoded; expect ~76 chars.
			if len(gotID) < 70 || len(gotID) > 85 {
				t.Errorf("identity length unexpected: %d (want ~76)", len(gotID))
			}

			if tc.wantIdentity != "" && gotID != tc.wantIdentity {
				t.Errorf("identity mismatch:\n got: %s\nwant: %s", gotID, tc.wantIdentity)
			}
			if tc.wantRecipient != "" && gotRcpt != tc.wantRecipient {
				t.Errorf("recipient mismatch (truncated):\n got: %s...\nwant: %s...",
					gotRcpt[:64], tc.wantRecipient[:64])
			}
		})
	}
}

// TestDerivePQSnapshot prints derived PQ identities and recipients
// for the static seeds. Used to (re-)generate expected values.
//
// Run with: go test -run TestDerivePQSnapshot -v
func TestDerivePQSnapshot(t *testing.T) {
	for _, tc := range pqTestVectors {
		seed, err := hex.DecodeString(tc.seedHex)
		if err != nil {
			t.Fatalf("decode seed: %v", err)
		}
		id, rcpt, err := derivePQ(seed)
		if err != nil {
			t.Fatalf("derivePQ %q: %v", tc.name, err)
		}
		t.Logf("\nname: %s\n  seed:      %s\n  identity:  %s\n  recipient: %s",
			tc.name, tc.seedHex, id, rcpt)
	}
}

// TestDerivePQRoundTrip checks that decoding the produced identity
// yields the original seed and that the recipient decodes to a
// 1216-byte payload.
func TestDerivePQRoundTrip(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)
	id, rcpt, err := derivePQ(seed)
	if err != nil {
		t.Fatalf("derivePQ: %v", err)
	}

	_, gotSeed, err := decodeBech32(id)
	if err != nil {
		t.Fatalf("decode identity: %v", err)
	}
	if !bytes.Equal(gotSeed, seed) {
		t.Errorf("decoded identity payload != seed: got %x, want %x", gotSeed, seed)
	}

	_, gotPub, err := decodeBech32(rcpt)
	if err != nil {
		t.Fatalf("decode recipient: %v", err)
	}
	if len(gotPub) != 1216 {
		t.Errorf("decoded recipient payload should be 1216 bytes, got %d", len(gotPub))
	}
}

// TestDerivePQSeedLength rejects non-32-byte seeds.
func TestDerivePQSeedLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		_, _, err := derivePQ(bytes.Repeat([]byte{0}, n))
		if err == nil {
			t.Errorf("expected error for seed length %d, got nil", n)
		}
	}
}

// TestDeriveFromSeedPQDispatch checks that the public API correctly
// dispatches to the PQ derivation now that it is wired up.
func TestDeriveFromSeedPQDispatch(t *testing.T) {
	seed := bytes.Repeat([]byte{0}, 32)
	got, err := DeriveFromSeed(seed, KeyTypePQ)
	if err != nil {
		t.Fatalf("DeriveFromSeed PQ: %v", err)
	}
	if got.Type != KeyTypePQ {
		t.Errorf("expected KeyTypePQ in result, got %v", got.Type)
	}
	if !strings.HasPrefix(got.Identity, "AGE-SECRET-KEY-PQ-1") {
		t.Errorf("wrong identity HRP: %q", got.Identity[:30])
	}
	if !strings.HasPrefix(got.Recipient, "age1pq1") {
		t.Errorf("wrong recipient HRP: %q", got.Recipient[:16])
	}
}
