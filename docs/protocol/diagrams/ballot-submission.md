# Ballot Submission Subprotocol Sequence Diagram

```mermaid
sequenceDiagram
    box rgb(255, 235, 204) Internet  / Election Admin Network
        participant VA as Voting Application
        participant DBB as Digital Ballot Box
    end

    activate VA
    Note over VA: Prepare Signed Ballot Message
    VA->>VA: Map selections to plaintext ballot encoding
    VA->>VA: Generate randomizers for ballot ciphertext
    VA->>VA: Naor-Yung Encrypt (ballot, Y) -> BallotCiphertext
    VA->>VA: Build BallotCryptogram {ballot_style, ciphertext}
    VA->>VA: Sign SignedBallotMsgData using PrivK_App -> Signature
    Note over VA: Ballot Prepared & Signed
    deactivate VA

    VA->>+DBB: Send Signed Ballot Message (SignedBallotMsgData, Signature)

    activate DBB
    Note right of DBB: Receive submission
    DBB->>DBB: Retrieve PubK_App for sender
    DBB->>DBB: Verify Signature using PubK_App (Success assumed)
    DBB->>DBB: Construct PBB Message (incl. Signed Ballot Message)
    DBB->>DBB: Append Message to Public Bulletin Board
    DBB->>DBB: Calculate Ballot Tracker = hash(PBB Message)
    DBB-->>-VA: Return Ballot Tracker
    deactivate DBB

    activate VA
    Note over VA: Store Ballot Tracker
    deactivate VA
```
