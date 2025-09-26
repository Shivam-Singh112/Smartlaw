

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SmartLaw
 * @dev A decentralized legal document management and verification system
 * @author SmartLaw Team
 */
contract Project {
    
    // Struct to represent a legal document
    struct LegalDocument {
        uint256 id;
        string title;
        string documentHash; // IPFS hash or SHA-256 hash of document
        address creator;
        address[] signatories;
        mapping(address => bool) signatures;
        uint256 createdAt;
        uint256 expiresAt;
        bool isActive;
        DocumentStatus status;
    }
    
    // Enum for document status
    enum DocumentStatus {
        DRAFT,
        PENDING_SIGNATURES,
        FULLY_SIGNED,
        EXPIRED,
        REVOKED
    }
    
    // State variables
    mapping(uint256 => LegalDocument) public documents;
    mapping(address => uint256[]) public userDocuments;
    uint256 public documentCounter;
    address public owner;
    
    // Events
    event DocumentCreated(uint256 indexed documentId, string title, address indexed creator);
    event DocumentSigned(uint256 indexed documentId, address indexed signatory);
    event DocumentStatusChanged(uint256 indexed documentId, DocumentStatus newStatus);
    event DocumentRevoked(uint256 indexed documentId, address indexed revokedBy);
    
    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Only contract owner can perform this action");
        _;
    }
    
    modifier onlyDocumentCreator(uint256 _documentId) {
        require(documents[_documentId].creator == msg.sender, "Only document creator can perform this action");
        _;
    }
    
    modifier documentExists(uint256 _documentId) {
        require(_documentId > 0 && _documentId <= documentCounter, "Document does not exist");
        _;
    }
    
    modifier documentActive(uint256 _documentId) {
        require(documents[_documentId].isActive, "Document is not active");
        require(block.timestamp <= documents[_documentId].expiresAt, "Document has expired");
        _;
    }
    
    constructor() {
        owner = msg.sender;
        documentCounter = 0;
    }
    
    /**
     * @dev Core Function 1: Create a new legal document
     * @param _title Title of the document
     * @param _documentHash Hash of the document content (IPFS hash recommended)
     * @param _signatories Array of addresses that need to sign the document
     * @param _validityPeriod Validity period in seconds from creation time
     */
    function createDocument(
        string memory _title,
        string memory _documentHash,
        address[] memory _signatories,
        uint256 _validityPeriod
    ) public returns (uint256) {
        require(bytes(_title).length > 0, "Document title cannot be empty");
        require(bytes(_documentHash).length > 0, "Document hash cannot be empty");
        require(_signatories.length > 0, "At least one signatory is required");
        require(_validityPeriod > 0, "Validity period must be greater than 0");
        
        documentCounter++;
        uint256 documentId = documentCounter;
        
        LegalDocument storage newDoc = documents[documentId];
        newDoc.id = documentId;
        newDoc.title = _title;
        newDoc.documentHash = _documentHash;
        newDoc.creator = msg.sender;
        newDoc.signatories = _signatories;
        newDoc.createdAt = block.timestamp;
        newDoc.expiresAt = block.timestamp + _validityPeriod;
        newDoc.isActive = true;
        newDoc.status = DocumentStatus.PENDING_SIGNATURES;
        
        // Add document to creator's list
        userDocuments[msg.sender].push(documentId);
        
        // Add document to each signatory's list
        for (uint256 i = 0; i < _signatories.length; i++) {
            userDocuments[_signatories[i]].push(documentId);
        }
        
        emit DocumentCreated(documentId, _title, msg.sender);
        emit DocumentStatusChanged(documentId, DocumentStatus.PENDING_SIGNATURES);
        
        return documentId;
    }
    
    /**
     * @dev Core Function 2: Sign a legal document
     * @param _documentId ID of the document to sign
     */
    function signDocument(uint256 _documentId) 
        public 
        documentExists(_documentId) 
        documentActive(_documentId) 
    {
        LegalDocument storage doc = documents[_documentId];
        
        require(doc.status == DocumentStatus.PENDING_SIGNATURES, "Document is not in pending signatures state");
        require(!doc.signatures[msg.sender], "You have already signed this document");
        
        // Check if sender is authorized to sign
        bool isAuthorized = false;
        for (uint256 i = 0; i < doc.signatories.length; i++) {
            if (doc.signatories[i] == msg.sender) {
                isAuthorized = true;
                break;
            }
        }
        require(isAuthorized, "You are not authorized to sign this document");
        
        // Record the signature
        doc.signatures[msg.sender] = true;
        
        emit DocumentSigned(_documentId, msg.sender);
        
        // Check if all signatures are collected
        bool allSigned = true;
        for (uint256 i = 0; i < doc.signatories.length; i++) {
            if (!doc.signatures[doc.signatories[i]]) {
                allSigned = false;
                break;
            }
        }
        
        if (allSigned) {
            doc.status = DocumentStatus.FULLY_SIGNED;
            emit DocumentStatusChanged(_documentId, DocumentStatus.FULLY_SIGNED);
        }
    }
    
    /**
     * @dev Core Function 3: Verify document authenticity and signature status
     * @param _documentId ID of the document to verify
     * @param _documentHash Hash to verify against stored hash
     * @return isValid True if document is valid and authentic
     * @return status Current status of the document
     * @return signatureCount Number of signatures collected
     * @return totalSignatories Total number of required signatories
     */
    function verifyDocument(uint256 _documentId, string memory _documentHash) 
        public 
        view 
        documentExists(_documentId)
        returns (
            bool isValid,
            DocumentStatus status,
            uint256 signatureCount,
            uint256 totalSignatories
        ) 
    {
        LegalDocument storage doc = documents[_documentId];
        
        // Check if document hash matches
        bool hashMatches = keccak256(abi.encodePacked(doc.documentHash)) == keccak256(abi.encodePacked(_documentHash));
        
        // Count signatures
        uint256 sigCount = 0;
        for (uint256 i = 0; i < doc.signatories.length; i++) {
            if (doc.signatures[doc.signatories[i]]) {
                sigCount++;
            }
        }
        
        // Document is valid if hash matches, it's active, and not expired
        isValid = hashMatches && doc.isActive && (block.timestamp <= doc.expiresAt);
        
        return (isValid, doc.status, sigCount, doc.signatories.length);
    }
    
    // Additional helper functions
    
    /**
     * @dev Revoke a document (only by creator or contract owner)
     * @param _documentId ID of the document to revoke
     */
    function revokeDocument(uint256 _documentId) 
        public 
        documentExists(_documentId) 
    {
        LegalDocument storage doc = documents[_documentId];
        require(
            msg.sender == doc.creator || msg.sender == owner,
            "Only document creator or contract owner can revoke"
        );
        require(doc.isActive, "Document is already inactive");
        
        doc.isActive = false;
        doc.status = DocumentStatus.REVOKED;
        
        emit DocumentRevoked(_documentId, msg.sender);
        emit DocumentStatusChanged(_documentId, DocumentStatus.REVOKED);
    }
    
    /**
     * @dev Get document details
     * @param _documentId ID of the document
     * @return title Document title
     * @return documentHash Document hash
     * @return creator Creator address
     * @return createdAt Creation timestamp
     * @return expiresAt Expiration timestamp
     * @return isActive Whether document is active
     * @return status Current document status
     */
    function getDocumentDetails(uint256 _documentId)
        public
        view
        documentExists(_documentId)
        returns (
            string memory title,
            string memory documentHash,
            address creator,
            uint256 createdAt,
            uint256 expiresAt,
            bool isActive,
            DocumentStatus status
        )
    {
        LegalDocument storage doc = documents[_documentId];
        return (
            doc.title,
            doc.documentHash,
            doc.creator,
            doc.createdAt,
            doc.expiresAt,
            doc.isActive,
            doc.status
        );
    }
    
    /**
     * @dev Get user's documents
     * @param _user Address of the user
     * @return Array of document IDs associated with the user
     */
    function getUserDocuments(address _user) public view returns (uint256[] memory) {
        return userDocuments[_user];
    }
    
    /**
     * @dev Get document signatories
     * @param _documentId ID of the document
     * @return Array of signatory addresses
     */
    function getDocumentSignatories(uint256 _documentId) 
        public 
        view 
        documentExists(_documentId) 
        returns (address[] memory) 
    {
        return documents[_documentId].signatories;
    }
    
    /**
     * @dev Check if an address has signed a document
     * @param _documentId ID of the document
     * @param _signatory Address to check
     * @return True if the address has signed the document
     */
    function hasSigned(uint256 _documentId, address _signatory) 
        public 
        view 
        documentExists(_documentId) 
        returns (bool) 
    {
        return documents[_documentId].signatures[_signatory];
    }
}
