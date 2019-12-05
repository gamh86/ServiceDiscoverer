CC := g++
STD := -std=c++11
FLAGS := -fpermissive
DEBUG := 0

SOURCE_FILES := \
	servicediscoverer.cpp

OBJECT_FILES := ${SOURCE_FILES:.cpp=.o}

servicediscoverer: $(OBJECT_FILES)
	$(CC) -o servicediscoverer $(OBJECT_FILES)

$(OBJECT_FILES): $(SOURCE_FILES)
ifeq ($(DEBUG),1)
	@echo Compiling debug version
	$(CC) -g -DDEBUG $(STD) $(FLAGS) -c $(SOURCE_FILES)
else
	@echo Compiling normal version
	$(CC) $(STD) $(FLAGS) -c $(SOURCE_FILES)
endif
